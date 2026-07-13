"""Durable, idempotent execution layer (MR-17).

The interface autonomy calls to *do a thing exactly once, even across a crash*.
It journals every action through INTENT -> IN_PROGRESS -> COMMITTED/FAILED and
enforces the Phase-4 safety gate before anything fires.

Guarantees (and their honest limits):
  * Dedupe / at-most-once commit: a repeated trigger carrying the same
    idempotency key never re-runs a COMMITTED action — the stored result is
    returned. (Test: a replayed trigger executes ONCE.)
  * At-least-once dispatch across crashes: an action that crashed mid-flight is
    left IN_PROGRESS and re-dispatched by ``recover()`` on restart.
  * Exactly-once *observable* effect = at-least-once dispatch + an idempotency
    key handed to a key-idempotent effect. Effects that resume MUST dedupe on the
    key so recovery cannot double-fire the real-world side effect.
  * Bounded failure: a failing step is journaled and retried at most
    ``max_attempts`` times, then marked FAILED terminally — never retried forever.

Safety: the gate (``SafetyGate``) runs before the FIRST attempt. Anything it flags
is journaled AWAITING_APPROVAL and pushed onto the existing human approval queue
(``src/pending_actions.py``); the effect does not run. Because only gate-permitted
actions ever reach INTENT/IN_PROGRESS, ``recover()`` never bypasses the gate.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from src.durable.models import (
    JournalRecord,
    STATUS_AWAITING_APPROVAL,
    STATUS_COMMITTED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_INTENT,
)
from src.durable.safety import (
    BLAST_LOW,
    CATEGORY_GENERAL,
    GateDecision,
    SafetyGate,
    classify_category,
)
from src.durable.store import ExecutionStore, SqliteExecutionStore

logger = logging.getLogger(__name__)

# Result statuses mirror the terminal journal states the caller cares about.
RESULT_COMMITTED = STATUS_COMMITTED
RESULT_FAILED = STATUS_FAILED
RESULT_AWAITING_APPROVAL = STATUS_AWAITING_APPROVAL
RESULT_IN_PROGRESS = STATUS_IN_PROGRESS  # transient failure, retry pending

Effect = Callable[[], Any]
RecoveryHandler = Callable[[JournalRecord], Any]
ApprovalSink = Callable[[JournalRecord, GateDecision], None]


@dataclass(frozen=True)
class ExecutionResult:
    """What the executor returns to a caller."""

    status: str
    idempotency_key: str
    result: Any = None
    error: Optional[str] = None
    reason: Optional[str] = None

    @property
    def committed(self) -> bool:
        return self.status == RESULT_COMMITTED

    @property
    def awaiting_approval(self) -> bool:
        return self.status == RESULT_AWAITING_APPROVAL


def _default_db_path() -> str:
    from src.constants import DATA_DIR
    import os
    return os.path.join(DATA_DIR, "execution_journal.db")


def _default_approval_sink(record: JournalRecord, decision: GateDecision) -> None:
    """Push a gated action onto the existing human approval queue (fail-soft)."""
    try:
        from src import pending_actions
        pending_actions.stash(
            owner=record.owner,
            session_id=record.session_id,
            tool_type=record.action_type,
            content=str(record.payload),
        )
    except Exception as exc:  # noqa: BLE001 - queue push is best-effort
        logger.warning("durable approval stash failed for %s: %s",
                       record.idempotency_key, exc)


class DurableExecutor:
    """Journaled, idempotent, safety-gated executor. Injectable end-to-end."""

    def __init__(
        self,
        store: Optional[ExecutionStore] = None,
        gate: Optional[SafetyGate] = None,
        approval_sink: ApprovalSink = _default_approval_sink,
    ) -> None:
        self._store = store if store is not None else SqliteExecutionStore(_default_db_path())
        self._gate = gate if gate is not None else SafetyGate()
        self._approval_sink = approval_sink
        self._handlers: Dict[str, RecoveryHandler] = {}

    @property
    def store(self) -> ExecutionStore:
        return self._store

    def register_handler(self, action_type: str, handler: RecoveryHandler) -> None:
        """Register how to re-perform ``action_type`` during crash recovery.

        Without a handler a crashed action cannot be resumed and is failed closed.
        The handler receives the JournalRecord and MUST be idempotent w.r.t. the
        record's ``idempotency_key`` (recovery may re-invoke it)."""
        if not action_type:
            raise ValueError("action_type is required")
        self._handlers[action_type] = handler

    # ── public API ─────────────────────────────────────────────────────────
    def execute(
        self,
        idempotency_key: str,
        effect: Effect,
        *,
        action_type: str,
        category: Optional[str] = None,
        blast_radius: str = BLAST_LOW,
        session_id: Optional[str] = None,
        self_initiated: bool = False,
        owner: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        max_attempts: int = 3,
    ) -> ExecutionResult:
        """Run ``effect`` exactly once for ``idempotency_key``, safely and durably."""
        if not idempotency_key:
            raise ValueError("idempotency_key is required")
        if not action_type:
            raise ValueError("action_type is required")

        existing = self._store.get(idempotency_key)
        if existing is not None:
            replay = self._replay(existing, effect)
            if replay is not None:
                return replay
            # Non-terminal, non-approval record in this process -> resume it.
            return self._attempt(existing, effect)

        category = category or classify_category(action_type)
        record = JournalRecord(
            idempotency_key=idempotency_key, action_type=action_type,
            category=category, blast_radius=blast_radius, session_id=session_id,
            self_initiated=self_initiated, owner=owner,
            payload=payload or {}, max_attempts=max_attempts,
        )

        decision = self._gate.evaluate(
            category=category, blast_radius=blast_radius,
            session_id=session_id, self_initiated=self_initiated,
        )
        if decision.requires_human:
            return self._gate_to_approval(record, decision)

        record.status = STATUS_INTENT
        if not self._store.insert_intent(record):
            # Lost an insert race; re-read and replay/resume.
            current = self._store.get(idempotency_key)
            if current is None:
                return ExecutionResult(RESULT_FAILED, idempotency_key, error="lost record after race")
            replay = self._replay(current, effect)
            return replay if replay is not None else self._attempt(current, effect)
        return self._attempt(record, effect)

    def recover(self) -> List[ExecutionResult]:
        """Resume actions left IN_PROGRESS/INTENT by a crash. Call once on startup.

        Only gate-permitted actions ever reach these states, so recovery never
        bypasses the safety gate. Unresumable records (no handler, or attempts
        exhausted) are failed closed, not retried blindly."""
        results: List[ExecutionResult] = []
        pending = self._store.list_by_status(STATUS_IN_PROGRESS) + \
            self._store.list_by_status(STATUS_INTENT)
        for record in pending:
            handler = self._handlers.get(record.action_type)
            if handler is None:
                self._store.update(record.idempotency_key, status=STATUS_FAILED,
                                   error="no recovery handler registered")
                results.append(ExecutionResult(RESULT_FAILED, record.idempotency_key,
                                               error="no recovery handler registered"))
                continue
            results.append(self._attempt(record, lambda h=handler, r=record: h(r)))
        return results

    def get(self, idempotency_key: str) -> Optional[JournalRecord]:
        return self._store.get(idempotency_key)

    # ── internals ──────────────────────────────────────────────────────────
    def _replay(self, record: JournalRecord, effect: Effect) -> Optional[ExecutionResult]:
        """Return a result for an already-terminal/awaiting record, else None."""
        if record.status == STATUS_COMMITTED:
            return ExecutionResult(RESULT_COMMITTED, record.idempotency_key,
                                   result=record.result, reason="idempotent replay")
        if record.status == STATUS_FAILED:
            return ExecutionResult(RESULT_FAILED, record.idempotency_key,
                                   error=record.error, reason="terminal failure; not retried")
        if record.status == STATUS_AWAITING_APPROVAL:
            return ExecutionResult(RESULT_AWAITING_APPROVAL, record.idempotency_key,
                                   reason="awaiting human approval")
        return None

    def _gate_to_approval(self, record: JournalRecord, decision: GateDecision) -> ExecutionResult:
        record.status = STATUS_AWAITING_APPROVAL
        record.error = decision.reason
        self._store.insert_intent(record)
        try:
            self._approval_sink(record, decision)
        except Exception as exc:  # noqa: BLE001 - never let queueing crash the caller
            logger.warning("approval sink error for %s: %s", record.idempotency_key, exc)
        logger.info("durable action %s gated to human approval: %s",
                    record.idempotency_key, decision.reason)
        return ExecutionResult(RESULT_AWAITING_APPROVAL, record.idempotency_key,
                               reason=decision.reason)

    def _attempt(self, record: JournalRecord, effect: Effect) -> ExecutionResult:
        """Perform one bounded attempt. Marks IN_PROGRESS *before* the side effect
        so a crash is always recoverable; commits the result *after*."""
        key = record.idempotency_key
        if record.attempts_exhausted():
            self._store.update(key, status=STATUS_FAILED, error="max attempts exhausted")
            return ExecutionResult(RESULT_FAILED, key, error="max attempts exhausted",
                                   reason="not retried forever")

        attempts = record.attempts + 1
        self._store.update(key, status=STATUS_IN_PROGRESS, attempts=attempts)
        try:
            result = effect()
        except Exception as exc:  # noqa: BLE001 - failures are journaled, not raised
            exhausted = attempts >= record.max_attempts
            status = STATUS_FAILED if exhausted else STATUS_IN_PROGRESS
            self._store.update(key, status=status, error=repr(exc))
            logger.warning("durable action %s attempt %d/%d failed: %r",
                           key, attempts, record.max_attempts, exc)
            if exhausted:
                return ExecutionResult(RESULT_FAILED, key, error=repr(exc),
                                       reason="attempts exhausted; not retried")
            return ExecutionResult(RESULT_IN_PROGRESS, key, error=repr(exc),
                                   reason="attempt failed; retry pending recovery")

        # Commit AFTER the effect. A crash between here and the write leaves the
        # record IN_PROGRESS; recover() re-dispatches to the (idempotent) handler.
        self._store.update(key, status=STATUS_COMMITTED, result=result)
        return ExecutionResult(RESULT_COMMITTED, key, result=result)
