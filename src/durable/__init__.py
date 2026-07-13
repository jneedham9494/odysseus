"""Durable execution + idempotency layer (MR-17).

A journaled execution layer so a self-initiated / multi-step action survives a
crash and never double-fires. See ``executor.DurableExecutor`` for the entry
point autonomy calls, ``safety.SafetyGate`` for the Phase-4 initiation gate, and
``store.ExecutionStore`` for the Postgres-ready storage seam.

SAFE-BY-DEFAULT / OFF-BY-DEFAULT: nothing self-initiates unless the operator
explicitly enables the global autonomy switch; money / people / deletion /
physical actions are HITL-forever regardless of any setting.
"""
from __future__ import annotations

from src.durable.executor import (
    DurableExecutor,
    ExecutionResult,
    RESULT_AWAITING_APPROVAL,
    RESULT_COMMITTED,
    RESULT_FAILED,
    RESULT_IN_PROGRESS,
)
from src.durable.models import (
    JournalRecord,
    STATUS_AWAITING_APPROVAL,
    STATUS_COMMITTED,
    STATUS_FAILED,
    STATUS_IN_PROGRESS,
    STATUS_INTENT,
)
from src.durable.safety import (
    BLAST_HIGH,
    BLAST_LOW,
    BLAST_MEDIUM,
    CATEGORY_DELETION,
    CATEGORY_MONEY,
    CATEGORY_PEOPLE,
    CATEGORY_PHYSICAL,
    GateDecision,
    HITL_FOREVER,
    SafetyGate,
)
from src.durable.store import ExecutionStore, SqliteExecutionStore

__all__ = [
    "DurableExecutor", "ExecutionResult",
    "RESULT_AWAITING_APPROVAL", "RESULT_COMMITTED", "RESULT_FAILED", "RESULT_IN_PROGRESS",
    "JournalRecord",
    "STATUS_AWAITING_APPROVAL", "STATUS_COMMITTED", "STATUS_FAILED",
    "STATUS_IN_PROGRESS", "STATUS_INTENT",
    "SafetyGate", "GateDecision", "HITL_FOREVER",
    "BLAST_HIGH", "BLAST_MEDIUM", "BLAST_LOW",
    "CATEGORY_MONEY", "CATEGORY_PEOPLE", "CATEGORY_DELETION", "CATEGORY_PHYSICAL",
    "ExecutionStore", "SqliteExecutionStore",
]
