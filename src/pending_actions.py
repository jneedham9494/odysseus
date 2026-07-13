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
from src import tool_policy_table
from src.tool_security import (
    TIER_HITL,
    TIER_WRITE,
    actuator_tier,
)

logger = logging.getLogger(__name__)

PENDING_DB = os.path.join(DATA_DIR, "pending_actions.db")

# Approval gating (requires_approval / is_mutating_tool) now flows through the
# actuator tiering classifier ``src.tool_security.actuator_tier`` (MR-16). The
# base policy-table-derived sets below are retained as the AUDIT surface: the
# actuator classifier gates a proven superset of them (see
# ``tests/test_actuator_superset.py``), and other modules / characterization
# tests still read them from here.
#
# DERIVED from the single source of truth in src.tool_policy_table — see that
# module's ``_TABLE`` for the per-tool classification.
DEFAULT_GATED_TOOLS = tool_policy_table.GATED_TOOLS
# api_call / app_api are gated ONLY for write methods — read-only GET/HEAD calls
# (e.g. "is anyone home?", "what's my UPS load?") run freely so the gate isn't noisy.
_METHOD_AWARE_TOOLS = tool_policy_table.METHOD_AWARE_TOOLS
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
# MCP tool-name prefixes to gate (browser-automation tools register as e.g.
# "browser_navigate", "browser_click").
GATED_MCP_PREFIXES = tool_policy_table.GATED_PREFIXES


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


# High-risk real-world mutators that have their own confirm path in normal
# operation (e.g. send_email via agent_email_confirm) but MUST also be caught by
# the fail-closed net if the normal policy can't be evaluated. Listed here, not
# in DEFAULT_GATED_TOOLS, so normal-operation behaviour is unchanged.
# DERIVED from src.tool_policy_table (the ``failclosed_mutator`` flag). Retained
# as the audit surface; ``is_mutating_tool`` below classifies via actuator_tier.
_FAILCLOSED_EXTRA_MUTATORS = tool_policy_table.FAILCLOSED_EXTRA_MUTATORS


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
        _notify(pid, summary, tool_type)
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


def _notify(pid: str, summary: str, tool_type: str = "") -> None:
    """Best-effort ntfy notification. No-op unless the ``agent_tool_confirm_ntfy``
    setting holds a full ntfy topic URL.

    When ``app_base_url`` is set, the push carries categorized one-tap
    **Approve** / **Reject** http-action buttons (``src/ntfy_actions.py``) wired
    to the approval-queue routes, so the action can be decided from the phone.
    Without a base URL there is nowhere to point the buttons, so it degrades to
    a plain high-priority alert."""
    url = get_setting("agent_tool_confirm_ntfy", None)
    if not url:
        return
    import urllib.request

    from src import ntfy_actions

    base = (get_setting("app_base_url", "") or "").rstrip("/")
    if base:
        headers = ntfy_actions.build_approval_headers(pid, tool_type, base)
    else:
        headers = {
            "Title": "Assistant action needs approval",
            "Priority": "high",
            "Tags": "warning",
        }
    # One-tap kill-switch (preserved from the kill-switch rung): a headless ntfy
    # http action that HALTS all autonomous action, appended to the approve/reject
    # buttons. Only added when a kill-token is configured (see autonomy_routes).
    kill_token = get_setting("autonomy_kill_token", "") or ""
    if base and kill_token:
        halt = (
            f"http, HALT autonomy, {base}/api/autonomy/halt, method=POST, "
            f"headers.X-Autonomy-Token={kill_token}, clear=true"
        )
        existing = headers.get("Actions", "")
        headers["Actions"] = f"{existing}; {halt}" if existing else halt
    req = urllib.request.Request(url, data=summary.encode("utf-8"), headers=headers, method="POST")
    urllib.request.urlopen(req, timeout=5)
