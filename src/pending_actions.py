"""Generic approval queue for agent tool calls.

When the ``agent_tool_confirm`` setting is truthy, mutating / "real-world" tools
are intercepted in the agent loop (``src/agent_loop.py``), stashed here as
pending actions, and only executed after the user approves them via
``routes/pending_routes.py`` (or an actionable ntfy notification). This mirrors
the existing email draft-approval pattern (``mcp_servers/email_server.py``),
generalized to any tool.

Default OFF: with ``agent_tool_confirm`` unset, ``requires_approval()`` returns
False for everything and agent behavior is unchanged.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from typing import Any, Dict, List, Optional

from src.constants import DATA_DIR
from src.settings import get_setting
from src.tool_security import (
    TIER_HITL,
    TIER_WRITE,
    actuator_tier,
)

logger = logging.getLogger(__name__)

PENDING_DB = os.path.join(DATA_DIR, "pending_actions.db")

# Which actuators gate, and why, now lives in ONE policy table:
# ``src/tool_security.py`` (actuator_tier + the tier sets). This module consumes
# that table via ``requires_approval`` / ``is_mutating_tool`` below.

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _is_write_api_call(content: Optional[str]) -> bool:
    """For api_call/app_api, inspect the JSON args' HTTP method. Unparseable ->
    treat as write (fail closed)."""
    if not content:
        return True
    try:
        method = str(json.loads(content).get("method") or "GET").upper()
        return method in _WRITE_METHODS
    except Exception:
        return True


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())


def _conn() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    c = sqlite3.connect(PENDING_DB, timeout=10)
    c.row_factory = sqlite3.Row
    return c


def _init() -> None:
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_actions (
                id          TEXT PRIMARY KEY,
                owner       TEXT,
                session_id  TEXT,
                workspace   TEXT,
                tool_type   TEXT,
                content     TEXT,
                summary     TEXT,
                status      TEXT DEFAULT 'pending',
                result      TEXT,
                created_at  TEXT,
                decided_at  TEXT
            )
            """
        )


_init()


class ReplayBlock:
    """Minimal stand-in for a parsed tool block. ``execute_tool_block`` only
    reads ``.tool_type`` and ``.content``."""

    def __init__(self, tool_type: str, content: str):
        self.tool_type = tool_type
        self.content = content


def confirm_enabled() -> bool:
    return bool(get_setting("agent_tool_confirm", False))


def _extra_gated_tools() -> set:
    """Operator-configured extra tools to force through approval, from the
    ``agent_tool_confirm_tools`` setting. Lets an operator gate even a read/draft
    tool they consider sensitive; write/hitl tiers gate on their own."""
    extra = get_setting("agent_tool_confirm_tools", None)
    if isinstance(extra, str):
        return {t.strip() for t in extra.split(",") if t.strip()}
    if isinstance(extra, (list, set, tuple)):
        return {str(t).strip() for t in extra if str(t).strip()}
    return set()


def requires_approval(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    """True if this tool must be queued for human approval before running.

    Tier-aware (MR-16, see ``src/tool_security.actuator_tier``):
      - hitl-forever (money / people / deletion / physical) ALWAYS gates, even
        with ``agent_tool_confirm`` off - it can never be auto-delegated.
      - write-gated gates only when the operator enabled ``agent_tool_confirm``.
      - read / draft run freely, unless the operator explicitly listed the tool
        in ``agent_tool_confirm_tools``.
    """
    if not tool_type:
        return False
    tier = actuator_tier(tool_type, content)
    if tier == TIER_HITL:
        return True
    if tier == TIER_WRITE:
        return confirm_enabled()
    return confirm_enabled() and tool_type in _extra_gated_tools()


def is_mutating_tool(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    """Static (no settings/DB) classification of whether a tool mutates.

    Used by the fail-closed approval path: when the full ``requires_approval``
    policy can't be evaluated (e.g. a settings/DB read raised), this decides
    whether to gate. It reads only module constants (via ``actuator_tier``) so it
    cannot itself fail. A tool mutates if its tier is write-gated or hitl-forever;
    unknown tool types fall through to write-gated, so they count as mutating.
    """
    if not tool_type:
        return True
    return actuator_tier(tool_type, content) in (TIER_WRITE, TIER_HITL)


def _summarize(tool_type: str, content: str) -> str:
    body = (content or "").strip()
    first = body.splitlines()[0] if body else ""
    return f"{tool_type}: {first[:160]}"


def stash(
    owner: Optional[str],
    session_id: Optional[str],
    tool_type: str,
    content: str,
    workspace: Optional[str] = None,
) -> str:
    pid = uuid.uuid4().hex[:12]
    summary = _summarize(tool_type, content)
    with _conn() as c:
        c.execute(
            "INSERT INTO pending_actions "
            "(id, owner, session_id, workspace, tool_type, content, summary, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,'pending',?)",
            (pid, owner or "", session_id or "", workspace or "", tool_type,
             content or "", summary, _now()),
        )
    logger.info("Queued tool '%s' for approval (id=%s, owner=%s)", tool_type, pid, owner)
    try:
        _notify(pid, summary)
    except Exception as e:  # notification is best-effort
        logger.warning("pending-action notify failed: %s", e)
    return pid


def list_pending(owner: Optional[str]) -> List[Dict[str, Any]]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id, tool_type, summary, session_id, status, created_at "
            "FROM pending_actions WHERE status='pending' AND (owner=? OR ?='') "
            "ORDER BY created_at DESC",
            (owner or "", owner or ""),
        ).fetchall()
    return [dict(r) for r in rows]


def get(pid: str, owner: Optional[str] = None) -> Optional[Dict[str, Any]]:
    with _conn() as c:
        row = c.execute("SELECT * FROM pending_actions WHERE id=?", (pid,)).fetchone()
    if not row:
        return None
    d = dict(row)
    if owner and d.get("owner") and d["owner"] != owner:
        return None
    return d


def mark(pid: str, status: str, result: Optional[str] = None) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE pending_actions SET status=?, result=?, decided_at=? WHERE id=?",
            (status, result, _now(), pid),
        )


def _notify(pid: str, summary: str) -> None:
    """Best-effort ntfy notification. No-op unless the ``agent_tool_confirm_ntfy``
    setting holds a full ntfy topic URL. Adds a one-tap "view" action linking to
    the app when ``app_base_url`` is set."""
    url = get_setting("agent_tool_confirm_ntfy", None)
    if not url:
        return
    import urllib.request

    headers = {"Title": "Assistant action needs approval", "Priority": "high", "Tags": "warning"}
    base = (get_setting("app_base_url", "") or "").rstrip("/")
    if base:
        headers["Actions"] = f"view, Open queue, {base}/?pending={pid}"
    req = urllib.request.Request(url, data=summary.encode("utf-8"), headers=headers, method="POST")
    urllib.request.urlopen(req, timeout=5)
