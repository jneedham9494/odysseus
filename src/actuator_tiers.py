"""Actuator tiering policy table (MR-16).

Every actuator (agent tool) is classified into exactly ONE tier that fixes how
much autonomy the agent has with it:

  read          - inspection only, no world change. Auto-runs.
  draft         - produces a reviewable artifact (document / image) with no
                  external side effect. Auto-runs; the human reviews the draft.
  write-gated   - irreversible / high-blast-radius mutation. Held for human
                  approval via the pending-actions queue when approval is on.
  hitl-forever  - money / people / deletion / physical. ALWAYS human-approved,
                  ignoring every setting; can never be auto-delegated.

Adding an actuator is a POLICY-TABLE edit here (one entry), never model-path or
agent-loop code. Anything not explicitly listed as read/draft/hitl falls through
to write-gated: fail-closed, so a forgotten new tool is gated, not run.

This module is imported (and re-exported) by ``src/tool_security.py``, the
security-policy surface, and consumed by ``src/pending_actions.py`` for the
approval queue.
"""
from __future__ import annotations

import json
from typing import Dict, FrozenSet, Optional

TIER_READ = "read"
TIER_DRAFT = "draft"
TIER_WRITE = "write-gated"
TIER_HITL = "hitl-forever"

# The four un-delegatable categories, hardcoded. Membership here forces
# hitl-forever and CANNOT be downgraded by any setting; the value records WHY.
#   people   - messages / acts toward real humans with the user's authority
#   deletion - irreversible data loss
#   physical - real-world / device actuation
# money is category-detected on integration calls (see _MONEY_MARKERS below).
HITL_FOREVER_TOOLS: Dict[str, str] = {
    "send_email": "people",
    "reply_to_email": "people",
    "bulk_email": "people",
    "delete_email": "deletion",
    "delete_file": "deletion",
    "move_file": "deletion",
    "ui_control": "physical",
}

# read-only inspection actuators - safe to auto-run.
READ_TOOLS: FrozenSet[str] = frozenset({
    "read_file", "grep", "glob", "ls", "get_workspace",
    "web_search", "web_fetch", "search_chats",
    "list_models", "list_sessions", "list_emails", "read_email",
    "list_email_accounts", "resolve_contact",
    "list_served_models", "list_downloads", "list_cached_models",
    "search_hf_models", "list_serve_presets", "list_cookbook_servers",
    "tail_serve_output", "chat_with_model", "ask_teacher", "ask_user",
    "update_plan",
})

# draft-tier - builds a reviewable content artifact, no external effect.
DRAFT_TOOLS: FrozenSet[str] = frozenset({
    "create_document", "edit_document", "update_document", "suggest_document",
    "generate_image", "edit_image",
})

# write-gated - mutate real / persistent state; must pass the approval queue.
# Not required for correctness (unknown tools fall through to write-gated too)
# but kept explicit as an audit list of the KNOWN mutating surface.
WRITE_GATED_TOOLS: FrozenSet[str] = frozenset({
    "write_file", "edit_file", "bash", "python", "manage_bg_jobs",
    "manage_calendar", "manage_contact", "manage_memory", "manage_tasks",
    "manage_skills", "manage_notes", "manage_documents", "manage_endpoints",
    "manage_mcp", "manage_webhooks", "manage_tokens", "manage_settings",
    "manage_session", "create_session", "send_to_session", "pipeline",
    "archive_email", "mark_email_read",
    "download_model", "serve_model", "stop_served_model", "cancel_download",
    "adopt_served_model", "serve_preset",
    "trigger_research", "manage_research",
})

# MCP browser / automation prefixes - can submit forms or exfiltrate; gate.
_ACTUATOR_MCP_PREFIXES = ("browser_", "playwright_")

# Integration calls tiered at runtime by HTTP verb + target.
_METHOD_AWARE_ACTUATORS = ("api_call", "app_api")
_WRITE_HTTP_METHODS: FrozenSet[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
# Content markers meaning an integration write moves money -> hitl-forever.
# Liberal on purpose: a false positive only over-gates (safe); Firefly III is a
# live integration on this box.
_MONEY_MARKERS = (
    "firefly", "stripe", "paypal", "plaid", "coinbase", "wise",
    "/payment", "/transaction", "/transfer", "/payout", "/invoice",
)


def _api_call_tier(content: Optional[str]) -> str:
    """Tier an api_call / app_api by HTTP verb and target. Fail-closed: an
    unparseable or non-object payload is treated as a gated write."""
    if not content:
        return TIER_WRITE
    try:
        args = json.loads(content)
    except (ValueError, TypeError):
        return TIER_WRITE
    if not isinstance(args, dict):
        return TIER_WRITE
    method = str(args.get("method") or "GET").upper()
    if method not in _WRITE_HTTP_METHODS:
        return TIER_READ  # GET / HEAD / etc. - read-only integration call
    blob = content.lower()
    if any(marker in blob for marker in _MONEY_MARKERS):
        return TIER_HITL  # money movement
    if method == "DELETE":
        return TIER_HITL  # irreversible deletion
    return TIER_WRITE


def actuator_tier(tool_type: Optional[str], content: Optional[str] = None) -> str:
    """Return the autonomy tier for an actuator (read/draft/write-gated/
    hitl-forever).

    Fail-closed: an unknown or malformed tool name is treated as a gated write,
    never auto-run. hitl-forever wins over everything and ignores all settings -
    money, people, deletion and physical actions can never be auto-delegated.
    This function reads only module constants (plus a guarded JSON parse) so it
    cannot itself raise.
    """
    if not tool_type or not isinstance(tool_type, str):
        return TIER_WRITE
    # 1. Hardcoded, non-negotiable hitl-forever categories.
    if tool_type in HITL_FOREVER_TOOLS:
        return TIER_HITL
    # 2. Integration calls: verb / target decide (may escalate to hitl).
    if tool_type in _METHOD_AWARE_ACTUATORS:
        return _api_call_tier(content)
    # 3. Browser / automation MCP tools - world-affecting; gate as write.
    if tool_type.startswith(_ACTUATOR_MCP_PREFIXES):
        return TIER_WRITE
    # 4. Static table.
    if tool_type in READ_TOOLS:
        return TIER_READ
    if tool_type in DRAFT_TOOLS:
        return TIER_DRAFT
    if tool_type in WRITE_GATED_TOOLS:
        return TIER_WRITE
    # 5. Unknown actuator -> fail closed (gated).
    return TIER_WRITE
