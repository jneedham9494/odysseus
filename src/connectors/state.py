"""Per-(connector, owner) sync watermark store, backed by SQLite.

Mirrors the sqlite style of ``src/pending_actions.py`` (``_conn()`` with
``os.makedirs(DATA_DIR)`` and ``timeout=10``). The cursor is opaque to the
store; each connector defines its own comparison for the monotonicity guard.
The per-(connector, owner) primary key isolates owners so one owner's feed
advances without touching another's.
"""
from __future__ import annotations

import os
import sqlite3
import time
from typing import Optional

from src.constants import CONNECTOR_STATE_DB, DATA_DIR


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cursor_is_greater(new_cursor: str, old_cursor: Optional[str]) -> bool:
    """True if ``new_cursor`` should replace ``old_cursor`` (monotonic guard).

    Compares as int when both parse as int (Miniflux entry ids); otherwise
    falls back to lexical string comparison. Any None old cursor accepts.
    """
    if old_cursor is None:
        return True
    try:
        return int(new_cursor) > int(old_cursor)
    except (TypeError, ValueError):
        return str(new_cursor) > str(old_cursor)


class WatermarkStore:
    """SQLite-backed sync cursor keyed by (connector, owner)."""

    def __init__(self, db_path: str = CONNECTOR_STATE_DB):
        self._db_path = db_path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        os.makedirs(DATA_DIR, exist_ok=True)
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS connector_watermark (
                    connector       TEXT NOT NULL,
                    owner           TEXT NOT NULL,
                    cursor          TEXT,
                    last_synced_at  TEXT,
                    PRIMARY KEY (connector, owner)
                )
                """
            )

    def get_cursor(self, connector: str, owner: str) -> Optional[str]:
        """Return the stored cursor, or None on first sync (backfill window)."""
        if not connector or not owner:
            return None
        with self._conn() as conn:
            row = conn.execute(
                "SELECT cursor FROM connector_watermark WHERE connector = ? AND owner = ?",
                (connector, owner),
            ).fetchone()
        return row["cursor"] if row else None

    def advance(self, connector: str, owner: str, cursor: str) -> bool:
        """Advance the cursor if strictly greater than the stored one.

        Returns True if written, False if the guard rejected a stale/equal
        cursor. Also updates last_synced_at when written.
        """
        if not connector or not owner or cursor is None:
            return False
        with self._conn() as conn:
            current = self.get_cursor(connector, owner)
            if not _cursor_is_greater(str(cursor), current):
                return False
            conn.execute(
                """
                INSERT INTO connector_watermark (connector, owner, cursor, last_synced_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(connector, owner)
                DO UPDATE SET cursor = excluded.cursor,
                              last_synced_at = excluded.last_synced_at
                """,
                (connector, owner, str(cursor), _now()),
            )
        return True

    def reset(self, connector: str, owner: str) -> None:
        """Delete the row (for re-backfill / testing)."""
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM connector_watermark WHERE connector = ? AND owner = ?",
                (connector, owner),
            )
