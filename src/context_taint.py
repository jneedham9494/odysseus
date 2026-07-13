"""Context taint tracking — the EchoLeak / prompt-injection-to-action defense.

When a session ingests untrusted external content (web pages, browser DOM), that
context becomes *tainted*. Any later credentialed real-world action in that
session — send email, write API call, browser action — must then go through
human approval, even if auto-confirm is off, so a poisoned page cannot make the
agent act with the user's authority.

This is the pragmatic "tier-split" v1: instead of fully separate web vs
credentialed agents, one agent whose authority to *act* is revoked once it has
*read* something untrusted, until a human approves.

State is per-session and in-process (resets on app restart) — fine for this
defense, which only needs to hold within a conversation.
"""
from __future__ import annotations

from typing import Optional

from src import tool_policy_table

# --- Graded sensitivity labels (additive; do NOT change binary taint gating) ---
# Two orthogonal axes: *taint* (is the provenance attacker-controllable?) vs
# *sensitivity* (how sensitive is the content?). Membership in
# ``_TAINTED_SESSIONS`` remains the taint test; the stored value is the highest
# sensitivity label observed for that session (escalate-only, never downgraded).
SENSITIVITY_PUBLIC = "public"
SENSITIVITY_PERSONAL = "personal"
SENSITIVITY_SENSITIVE = "sensitive"
_SENSITIVITY_RANK = {
    SENSITIVITY_PUBLIC: 0,
    SENSITIVITY_PERSONAL: 1,
    SENSITIVITY_SENSITIVE: 2,
}
# Web/browser default. The label choice does NOT affect existing gating, which
# stays a binary membership check (see requires_taint_approval).
DEFAULT_TAINT_SENSITIVITY = SENSITIVITY_PUBLIC

# Provenance marker stamped onto connector-ingested content (see connectors).
TAINT_UNTRUSTED = "untrusted"

# session_id -> highest sensitivity label seen (membership == tainted, as before).
_TAINTED_SESSIONS: dict[str, str] = {}

# All tier/mutator classification below is DERIVED from the single source of
# truth in src.tool_policy_table (see that module's ``_TABLE`` / ``_PATTERN_TABLE``).
# Tools whose output is attacker-controllable external content.
# Derived from the single source of truth in tool_policy_table. The searxng MCP
# tool (`mcp__searxng__web_search`) is registered there as an untrusted source so
# its web results taint the session too.
_UNTRUSTED_SOURCE_TOOLS = tool_policy_table.UNTRUSTED_SOURCE_TOOLS
_UNTRUSTED_PREFIXES = tool_policy_table.UNTRUSTED_PREFIXES

# Content-source types (NOT tools) whose provenance is attacker-controllable.
# Connector-ingested content enters the agent via RAG retrieval, not a tool
# call, so it is classified by source_type rather than tool_type. This is the
# seam a later MR uses to taint a session when connector content is retrieved.
_UNTRUSTED_SOURCE_TYPE_PREFIX = "connector:"

# Real-world credentialed mutators that must not auto-fire in a tainted context.
_CREDENTIALED_MUTATORS = tool_policy_table.CREDENTIALED_MUTATORS
_METHOD_AWARE = tool_policy_table.METHOD_AWARE_TOOLS


def normalize_sensitivity(value: Optional[str]) -> str:
    """Coerce an arbitrary label to a known sensitivity, defaulting to public."""
    return value if value in _SENSITIVITY_RANK else DEFAULT_TAINT_SENSITIVITY


def mark_tainted(
    session_id: Optional[str], sensitivity: str = DEFAULT_TAINT_SENSITIVITY
) -> None:
    """Mark a session tainted, escalating (never downgrading) its sensitivity."""
    if not session_id:
        return
    sensitivity = normalize_sensitivity(sensitivity)
    current = _TAINTED_SESSIONS.get(session_id)
    if current is None or _SENSITIVITY_RANK[sensitivity] > _SENSITIVITY_RANK[current]:
        _TAINTED_SESSIONS[session_id] = sensitivity


def is_tainted(session_id: Optional[str]) -> bool:
    return bool(session_id) and session_id in _TAINTED_SESSIONS


def session_sensitivity(session_id: Optional[str]) -> Optional[str]:
    """Return the escalated (max-rank) sensitivity label, or None if untainted."""
    return _TAINTED_SESSIONS.get(session_id or "")


def clear(session_id: Optional[str]) -> None:
    _TAINTED_SESSIONS.pop(session_id or "", None)


def is_untrusted_source(tool_type: Optional[str]) -> bool:
    if not tool_type:
        return False
    return tool_type in _UNTRUSTED_SOURCE_TOOLS or tool_type.startswith(_UNTRUSTED_PREFIXES)


def is_untrusted_source_type(source_type: Optional[str]) -> bool:
    """True if RAG-ingested content of this source_type is attacker-controllable.

    Distinct from is_untrusted_source (which keys on an agent tool_type):
    connector content is not a tool, it enters via RAG retrieval.
    """
    return bool(source_type) and source_type.startswith(_UNTRUSTED_SOURCE_TYPE_PREFIX)


def row_is_untrusted(metadata: Optional[dict]) -> bool:
    """True if a retrieved RAG row's provenance is attacker-controllable.

    A row is untrusted if the write-path stamped ``taint=untrusted`` on it, or
    (belt-and-suspenders, in case a row predates the taint stamp) its
    ``source_type`` is a connector source. Non-dict / missing metadata is
    treated as trusted — only an explicit untrusted marker taints.
    """
    if not isinstance(metadata, dict):
        return False
    if metadata.get("taint") == TAINT_UNTRUSTED:
        return True
    return is_untrusted_source_type(metadata.get("source_type"))


def taint_from_retrieved_rows(session_id: Optional[str], rows: object) -> bool:
    """Taint ``session_id`` if any retrieved RAG row is untrusted.

    This is the retrieval-side enforcement seam (MR-2b): connector content is
    taint-stamped at write time, but only becomes active when *read* into a
    session's context. For each untrusted row, escalate the session to that
    row's stamped sensitivity (mark_tainted is escalate-only). After this,
    ``requires_taint_approval`` forces later credentialed mutators through human
    approval (EchoLeak / tier-split defense).

    Degrades safely: a falsy ``session_id`` (e.g. background ingestion / a
    sessionless retrieval) is a no-op returning False, so poisoned content
    ingested outside a conversation can never silently taint a live session.

    Args:
        session_id: The session consuming these rows, or None if sessionless.
        rows: An iterable of search-result dicts, each with a ``metadata`` dict.

    Returns:
        True if the session was tainted by at least one untrusted row.
    """
    if not session_id or not rows:
        return False
    tainted = False
    for row in rows:
        metadata = row.get("metadata") if isinstance(row, dict) else None
        if row_is_untrusted(metadata):
            mark_tainted(session_id, sensitivity=normalize_sensitivity(metadata.get("sensitivity")))
            tainted = True
    return tainted


def is_credentialed_mutator(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    if not tool_type:
        return False
    if tool_type in _CREDENTIALED_MUTATORS:
        return True
    if tool_type.startswith(_UNTRUSTED_PREFIXES):  # browser actions can submit/exfil
        return True
    if tool_type in _METHOD_AWARE:
        try:
            from src.pending_actions import _is_write_api_call
            return _is_write_api_call(content)
        except Exception:
            return True  # unknown method → treat as write (safe)
    return False


def requires_taint_approval(session_id: Optional[str], tool_type: Optional[str],
                            content: Optional[str] = None) -> bool:
    """A credentialed action in a tainted session must be human-approved."""
    return is_tainted(session_id) and is_credentialed_mutator(tool_type, content)
