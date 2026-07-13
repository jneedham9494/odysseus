"""MR-17 durable execution + idempotency tests.

Covers the three contractual properties plus the Phase-4 safety gate:
  1. a replayed trigger with the same idempotency key executes ONCE;
  2. a simulated crash mid-action resumes exactly-once (no double side-effect);
  3. a failed step is journaled and not silently retried forever;
  4. HITL-forever / autonomy-off / tainted+high-blast actions are gated to a human.

All side effects are mocked; the executor is driven purely through injected
stores/gates so nothing here touches app settings, taint state, or the queue.
"""
from __future__ import annotations

from typing import List, Optional

import pytest

from src.durable.executor import (
    DurableExecutor,
    RESULT_AWAITING_APPROVAL,
    RESULT_COMMITTED,
    RESULT_FAILED,
)
from src.durable.models import (
    JournalRecord,
    STATUS_COMMITTED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
)
from src.durable.safety import (
    BLAST_HIGH,
    BLAST_LOW,
    CATEGORY_MONEY,
    GateDecision,
    SafetyGate,
)
from src.durable.store import SqliteExecutionStore


# ── helpers ─────────────────────────────────────────────────────────────────
class KeyedSideEffect:
    """A mock side effect that is idempotent w.r.t. the idempotency key.

    ``applied`` records the OBSERVABLE effect (one entry per unique key);
    ``invocations`` records how many times it was called (dispatch count). The
    gap between them is what makes "at-least-once dispatch + exactly-once effect"
    visible to the tests.
    """

    def __init__(self) -> None:
        self.applied: List[str] = []
        self.invocations = 0

    def apply(self, key: str) -> dict:
        self.invocations += 1
        if key not in self.applied:
            self.applied.append(key)
        return {"key": key, "ok": True}


class CrashOnCommitStore(SqliteExecutionStore):
    """SQLite store that raises the first time it tries to persist a COMMIT,
    simulating a process crash *after* the side effect ran but *before* the
    commit was durably written."""

    def __init__(self, db_path: str) -> None:
        super().__init__(db_path)
        self.armed = True

    def update(self, idempotency_key: str, **fields) -> None:
        if self.armed and fields.get("status") == STATUS_COMMITTED:
            self.armed = False
            raise RuntimeError("simulated crash before commit persisted")
        super().update(idempotency_key, **fields)


def _permissive_gate() -> SafetyGate:
    # autonomy ON, never tainted -> gate lets general actions through so the
    # durability tests exercise the journal, not the gate.
    return SafetyGate(autonomy_enabled=lambda: True, is_tainted=lambda _s: False)


def _executor(db_path: str, gate: Optional[SafetyGate] = None) -> DurableExecutor:
    return DurableExecutor(
        store=SqliteExecutionStore(db_path),
        gate=gate or _permissive_gate(),
        approval_sink=lambda record, decision: None,
    )


# ── 1. dedupe: same key executes once ───────────────────────────────────────
def test_replayed_trigger_same_key_executes_once(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = _executor(db)
    side = KeyedSideEffect()
    key = "trigger-abc"

    first = ex.execute(key, lambda: side.apply(key), action_type="notify")
    second = ex.execute(key, lambda: side.apply(key), action_type="notify")
    third = ex.execute(key, lambda: side.apply(key), action_type="notify")

    assert first.status == RESULT_COMMITTED
    assert second.status == RESULT_COMMITTED
    assert third.status == RESULT_COMMITTED
    # The effect ran exactly once; replays returned the cached result.
    assert side.invocations == 1
    assert side.applied == [key]
    assert second.result == first.result == {"key": key, "ok": True}
    assert ex.get(key).status == STATUS_COMMITTED


# ── 2. crash mid-action resumes exactly-once ────────────────────────────────
def test_crash_mid_action_resumes_exactly_once(tmp_path):
    db = str(tmp_path / "journal.db")
    side = KeyedSideEffect()
    key = "action-xyz"

    # Executor 1 crashes on commit *after* the side effect has been applied.
    crash_store = CrashOnCommitStore(db)
    ex1 = DurableExecutor(store=crash_store, gate=_permissive_gate(),
                          approval_sink=lambda r, d: None)
    with pytest.raises(RuntimeError, match="simulated crash"):
        ex1.execute(key, lambda: side.apply(key), action_type="charge_report")

    # Side effect happened once; journal is stuck IN_PROGRESS (not committed).
    assert side.applied == [key]
    assert crash_store.get(key).status == STATUS_IN_PROGRESS

    # Restart: a fresh executor over the SAME db resumes via a registered,
    # key-idempotent handler.
    ex2 = _executor(db)
    ex2.register_handler("charge_report", lambda rec: side.apply(rec.idempotency_key))
    results = ex2.recover()

    assert len(results) == 1 and results[0].status == RESULT_COMMITTED
    assert ex2.get(key).status == STATUS_COMMITTED
    # Recovery re-dispatched (invocations == 2) but the OBSERVABLE side effect
    # fired exactly once — no double charge.
    assert side.invocations == 2
    assert side.applied == [key]


def test_recover_without_handler_fails_closed(tmp_path):
    db = str(tmp_path / "journal.db")
    side = KeyedSideEffect()
    key = "orphan"
    crash_store = CrashOnCommitStore(db)
    ex1 = DurableExecutor(store=crash_store, gate=_permissive_gate(),
                          approval_sink=lambda r, d: None)
    with pytest.raises(RuntimeError):
        ex1.execute(key, lambda: side.apply(key), action_type="unknown_action")

    ex2 = _executor(db)  # no handler registered
    results = ex2.recover()
    assert results[0].status == RESULT_FAILED
    assert ex2.get(key).status == STATUS_FAILED
    assert side.invocations == 1  # never re-dispatched


# ── 3. failed step journaled, not retried forever ───────────────────────────
def test_failed_step_is_bounded_and_journaled(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = _executor(db)
    calls = {"n": 0}

    def always_fails():
        calls["n"] += 1
        raise ValueError("boom")

    key = "doomed"
    # Drive attempts: one per execute() call. max_attempts defaults to 3.
    statuses = [ex.execute(key, always_fails, action_type="flaky").status
                for _ in range(6)]

    rec = ex.get(key)
    assert rec.status == STATUS_FAILED
    assert "boom" in (rec.error or "")
    # Bounded: exactly max_attempts real invocations, then terminal — the extra
    # execute() calls returned the cached FAILED without touching the effect.
    assert calls["n"] == 3
    assert rec.attempts == 3
    assert statuses[-1] == RESULT_FAILED


def test_recover_stops_after_attempts_exhausted(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = _executor(db)
    calls = {"n": 0}

    def always_fails(_rec=None):
        calls["n"] += 1
        raise ValueError("nope")

    key = "flaky2"
    ex.register_handler("flaky2", always_fails)
    ex.execute(key, always_fails, action_type="flaky2", max_attempts=2)
    # First execute() burned attempt 1 (status IN_PROGRESS). Recover repeatedly;
    # it must stop re-dispatching once attempts hit the cap.
    for _ in range(5):
        ex.recover()

    assert calls["n"] == 2  # attempt 1 (execute) + attempt 2 (first recover)
    assert ex.get(key).status == STATUS_FAILED


# ── 4. Phase-4 safety gate ──────────────────────────────────────────────────
def test_money_category_is_hitl_forever_even_with_autonomy_on(tmp_path):
    db = str(tmp_path / "journal.db")
    stashed = []
    ex = DurableExecutor(
        store=SqliteExecutionStore(db),
        gate=SafetyGate(autonomy_enabled=lambda: True, is_tainted=lambda _s: False),
        approval_sink=lambda record, decision: stashed.append(record.idempotency_key),
    )
    side = KeyedSideEffect()
    key = "pay-rent"
    res = ex.execute(key, lambda: side.apply(key), action_type="pay",
                     category=CATEGORY_MONEY, self_initiated=True)

    assert res.status == RESULT_AWAITING_APPROVAL
    assert side.invocations == 0            # effect never ran
    assert stashed == [key]                 # routed to human approval queue
    assert ex.get(key).status == "awaiting_approval"


def test_self_initiated_blocked_when_autonomy_disabled(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = DurableExecutor(
        store=SqliteExecutionStore(db),
        gate=SafetyGate(autonomy_enabled=lambda: False, is_tainted=lambda _s: False),
        approval_sink=lambda r, d: None,
    )
    side = KeyedSideEffect()
    res = ex.execute("self-1", lambda: side.apply("self-1"), action_type="notify",
                     self_initiated=True)
    assert res.status == RESULT_AWAITING_APPROVAL
    assert side.invocations == 0


def test_tainted_high_blast_requires_human(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = DurableExecutor(
        store=SqliteExecutionStore(db),
        gate=SafetyGate(autonomy_enabled=lambda: True, is_tainted=lambda _s: True),
        approval_sink=lambda r, d: None,
    )
    side = KeyedSideEffect()
    res = ex.execute("t-1", lambda: side.apply("t-1"), action_type="api_call",
                     blast_radius=BLAST_HIGH, session_id="s1", self_initiated=False)
    assert res.status == RESULT_AWAITING_APPROVAL
    assert side.invocations == 0


def test_gate_evaluation_error_fails_closed():
    def boom() -> bool:
        raise RuntimeError("settings unreadable")

    gate = SafetyGate(autonomy_enabled=boom, is_tainted=lambda _s: False)
    decision = gate.evaluate(category="general", blast_radius=BLAST_LOW,
                             session_id=None, self_initiated=True)
    assert isinstance(decision, GateDecision)
    assert decision.requires_human is True


def test_permitted_non_self_initiated_action_runs(tmp_path):
    db = str(tmp_path / "journal.db")
    ex = _executor(db)
    side = KeyedSideEffect()
    res = ex.execute("ok-1", lambda: side.apply("ok-1"), action_type="notify",
                     self_initiated=False)
    assert res.status == RESULT_COMMITTED
    assert side.applied == ["ok-1"]
