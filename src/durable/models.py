"""Data model for the durable execution journal (MR-17).

A JournalRecord is the durable record of one attempted action, keyed by an
*idempotency key*. Its ``status`` moves monotonically through a small lifecycle;
the executor never resurrects a terminal record except via an explicit reset.

Storage-agnostic on purpose: these are plain dataclasses so the same records can
be persisted by the SQLite store today and a Postgres store later (the eventual
MR-1). No ORM, no SQL, no I/O here.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


# ── Journal lifecycle states ────────────────────────────────────────────────
# INTENT           -> recorded before the side effect; nothing has fired yet.
# IN_PROGRESS      -> the side effect is being attempted (or was, at crash time).
# COMMITTED        -> terminal success; result is stored, effect must not re-fire.
# FAILED           -> terminal failure; NOT silently retried (bounded attempts).
# AWAITING_APPROVAL-> gated by the safety layer; a human must approve first.
STATUS_INTENT = "intent"
STATUS_IN_PROGRESS = "in_progress"
STATUS_COMMITTED = "committed"
STATUS_FAILED = "failed"
STATUS_AWAITING_APPROVAL = "awaiting_approval"

TERMINAL_STATES = frozenset({STATUS_COMMITTED, STATUS_FAILED})
# States a recovery pass may resume (a crash can only leave these two).
RESUMABLE_STATES = frozenset({STATUS_INTENT, STATUS_IN_PROGRESS})
ALL_STATES = frozenset({
    STATUS_INTENT, STATUS_IN_PROGRESS, STATUS_COMMITTED,
    STATUS_FAILED, STATUS_AWAITING_APPROVAL,
})


def _now() -> str:
    """ISO-8601 UTC timestamp (second precision), matching sibling stores."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


@dataclass
class JournalRecord:
    """One durable action, identified by its idempotency key.

    ``payload`` is opaque intent data the recovery handler needs to re-perform
    the action after a crash; ``result`` holds the committed return value.
    """

    idempotency_key: str
    action_type: str
    status: str = STATUS_INTENT
    category: str = "general"
    blast_radius: str = "low"
    session_id: Optional[str] = None
    self_initiated: bool = False
    owner: Optional[str] = None
    attempts: int = 0
    max_attempts: int = 3
    payload: Dict[str, Any] = field(default_factory=dict)
    result: Optional[Any] = None
    error: Optional[str] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATES

    def attempts_exhausted(self) -> bool:
        return self.attempts >= self.max_attempts
