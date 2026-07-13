"""Storage abstraction for the durable execution journal (MR-17).

``ExecutionStore`` is the seam. SQLite backs it today (``data/execution_journal.db``);
the eventual MR-1 Postgres deployment implements the SAME abstract interface, so
no caller changes when the backend swaps. All SQL lives here — the journal and
executor above speak only in ``JournalRecord`` objects.

Concurrency: every method takes a process-local lock and uses one short SQLite
transaction, so intent-insert / status-transition races resolve deterministically.
``insert_intent`` is the atomic dedupe primitive: a second insert with an existing
key returns ``False`` rather than creating a duplicate.
"""
from __future__ import annotations

import abc
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional

from src.durable.models import (
    JournalRecord,
    _now,
)


class ExecutionStore(abc.ABC):
    """Backend-agnostic persistence for JournalRecords.

    A record is uniquely keyed by ``idempotency_key``. Implementations MUST make
    ``insert_intent`` atomic (unique-key insert that fails closed on conflict).
    """

    @abc.abstractmethod
    def insert_intent(self, record: JournalRecord) -> bool:
        """Insert a new record. Return False if the key already exists (dedupe)."""

    @abc.abstractmethod
    def get(self, idempotency_key: str) -> Optional[JournalRecord]:
        """Return the record for a key, or None."""

    @abc.abstractmethod
    def update(self, idempotency_key: str, **fields: Any) -> None:
        """Patch mutable columns of an existing record; refresh updated_at."""

    @abc.abstractmethod
    def list_by_status(self, status: str) -> List[JournalRecord]:
        """Return all records currently in ``status`` (oldest first)."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release any backend resources."""


# Columns the executor is permitted to patch after insert. Anything else raises,
# so a typo can't silently no-op a status transition.
_MUTABLE_COLUMNS = frozenset({
    "status", "attempts", "result", "error", "updated_at",
})


class SqliteExecutionStore(ExecutionStore):
    """SQLite-backed store. Written Postgres-ready: no SQLite-only SQL beyond the
    guarded ``CREATE TABLE IF NOT EXISTS``; params are positional and portable."""

    def __init__(self, db_path: str) -> None:
        if not db_path:
            raise ValueError("db_path is required")
        self._db_path = db_path
        self._lock = threading.Lock()
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self._db_path, timeout=10)
        c.row_factory = sqlite3.Row
        return c

    def _init_schema(self) -> None:
        with self._lock, self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS execution_journal (
                    idempotency_key TEXT PRIMARY KEY,
                    action_type     TEXT NOT NULL,
                    status          TEXT NOT NULL,
                    category        TEXT NOT NULL DEFAULT 'general',
                    blast_radius    TEXT NOT NULL DEFAULT 'low',
                    session_id      TEXT,
                    self_initiated  INTEGER NOT NULL DEFAULT 0,
                    owner           TEXT,
                    attempts        INTEGER NOT NULL DEFAULT 0,
                    max_attempts    INTEGER NOT NULL DEFAULT 3,
                    payload         TEXT,
                    result          TEXT,
                    error           TEXT,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                )
                """
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS ix_execution_journal_status "
                "ON execution_journal(status)"
            )

    # ── mapping ────────────────────────────────────────────────────────────
    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> JournalRecord:
        return JournalRecord(
            idempotency_key=row["idempotency_key"],
            action_type=row["action_type"],
            status=row["status"],
            category=row["category"],
            blast_radius=row["blast_radius"],
            session_id=row["session_id"],
            self_initiated=bool(row["self_initiated"]),
            owner=row["owner"],
            attempts=row["attempts"],
            max_attempts=row["max_attempts"],
            payload=json.loads(row["payload"]) if row["payload"] else {},
            result=json.loads(row["result"]) if row["result"] is not None else None,
            error=row["error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ── ExecutionStore ─────────────────────────────────────────────────────
    def insert_intent(self, record: JournalRecord) -> bool:
        with self._lock, self._conn() as c:
            try:
                c.execute(
                    "INSERT INTO execution_journal ("
                    "idempotency_key, action_type, status, category, blast_radius, "
                    "session_id, self_initiated, owner, attempts, max_attempts, "
                    "payload, result, error, created_at, updated_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        record.idempotency_key, record.action_type, record.status,
                        record.category, record.blast_radius, record.session_id,
                        1 if record.self_initiated else 0, record.owner,
                        record.attempts, record.max_attempts,
                        json.dumps(record.payload),
                        None if record.result is None else json.dumps(record.result),
                        record.error, record.created_at, record.updated_at,
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False  # key already present -> dedupe, fail closed to caller

    def get(self, idempotency_key: str) -> Optional[JournalRecord]:
        with self._lock, self._conn() as c:
            row = c.execute(
                "SELECT * FROM execution_journal WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        return self._row_to_record(row) if row else None

    def update(self, idempotency_key: str, **fields: Any) -> None:
        patch: Dict[str, Any] = dict(fields)
        unknown = set(patch) - _MUTABLE_COLUMNS
        if unknown:
            raise ValueError(f"cannot update columns: {sorted(unknown)}")
        if "result" in patch and patch["result"] is not None:
            patch["result"] = json.dumps(patch["result"])
        patch["updated_at"] = _now()
        cols = ", ".join(f"{k}=?" for k in patch)
        with self._lock, self._conn() as c:
            c.execute(
                f"UPDATE execution_journal SET {cols} WHERE idempotency_key=?",
                (*patch.values(), idempotency_key),
            )

    def list_by_status(self, status: str) -> List[JournalRecord]:
        with self._lock, self._conn() as c:
            rows = c.execute(
                "SELECT * FROM execution_journal WHERE status=? ORDER BY created_at ASC",
                (status,),
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def close(self) -> None:  # sqlite connections are per-call; nothing to hold
        return None
