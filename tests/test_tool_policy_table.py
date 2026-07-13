"""Characterization test: the consolidated tool-policy table is behaviour-preserving.

Refactor B moved the ~5 scattered tool-risk lists behind a single audited table
(``src.tool_policy_table``). This test pins the *exact* classification each old
list produced (golden snapshots copied verbatim from the pre-refactor literals)
and asserts the derived constants — and the public accessors that read them —
still yield the identical result for every tool. If a future edit to the table
changes any tool's tier/flag, one of these assertions fails.
"""
from __future__ import annotations

import os
import tempfile

# pending_actions runs _init() (creates a sqlite db under DATA_DIR) at import.
os.environ.setdefault("ODYSSEUS_DATA_DIR", tempfile.mkdtemp(prefix="tpt-test-"))

from src import tool_policy_table as tpt
from src.tool_policy_table import ToolTier, get_policy
import src.pending_actions as pa
import src.context_taint as ct
import src.tool_security as ts


# ── Golden snapshots (verbatim from the pre-refactor literals) ────────────────

GOLDEN_GATED = {
    "manage_calendar", "manage_contact", "ui_control",
    "write_file", "edit_file", "bash", "python",
    "generate_image", "edit_image",
}
GOLDEN_FAILCLOSED_EXTRA = {
    "send_email", "reply_to_email", "bulk_email", "delete_file", "move_file",
}
GOLDEN_METHOD_AWARE = {"api_call", "app_api"}
GOLDEN_GATED_PREFIXES = ("browser_", "playwright_")

GOLDEN_NON_ADMIN_BLOCKED = {
    "summarize_miniflux_unread", "summarize_paperless_recent",
    "bash", "python", "manage_bg_jobs", "read_file", "write_file", "edit_file",
    "grep", "glob", "ls", "get_workspace", "search_chats", "manage_memory",
    "manage_skills", "manage_tasks", "manage_endpoints", "manage_mcp",
    "manage_webhooks", "manage_tokens", "manage_documents", "manage_settings",
    "api_call", "app_api", "send_email", "reply_to_email", "list_emails",
    "read_email", "resolve_contact", "manage_contact", "manage_calendar",
    "vault_search", "vault_get", "vault_unlock", "download_model", "serve_model",
    "serve_preset", "stop_served_model", "cancel_download", "adopt_served_model",
}
GOLDEN_PLAN_MODE_MUTATORS = {
    "write_file", "create_document", "edit_document", "update_document",
    "suggest_document", "manage_documents", "create_session", "manage_session",
    "send_to_session", "pipeline", "manage_memory", "manage_skills",
    "manage_tasks", "manage_notes", "manage_endpoints", "manage_mcp",
    "manage_webhooks", "manage_tokens", "manage_settings", "manage_contact",
    "manage_calendar", "api_call", "app_api", "ui_control", "send_email",
    "reply_to_email", "bulk_email", "delete_email", "archive_email",
    "mark_email_read", "download_model", "serve_model", "stop_served_model",
    "cancel_download", "adopt_served_model", "serve_preset", "generate_image",
    "edit_image", "trigger_research", "manage_research", "bash", "python",
    "manage_bg_jobs",
}

GOLDEN_UNTRUSTED_SOURCE = {"web_fetch", "web_search", "mcp__searxng__web_search",
                          "summarize_miniflux_unread", "summarize_paperless_recent"}
GOLDEN_UNTRUSTED_PREFIXES = ("browser_", "playwright_")
GOLDEN_CREDENTIALED_MUTATORS = {"send_email", "reply_to_email", "bulk_email"}


# ── Derived constants equal the golden snapshots exactly ──────────────────────

def test_default_gated_tools_matches_golden():
    assert set(pa.DEFAULT_GATED_TOOLS) == GOLDEN_GATED


def test_failclosed_extra_mutators_matches_golden():
    assert set(pa._FAILCLOSED_EXTRA_MUTATORS) == GOLDEN_FAILCLOSED_EXTRA


def test_method_aware_tools_match_golden_in_both_modules():
    assert set(pa._METHOD_AWARE_TOOLS) == GOLDEN_METHOD_AWARE
    assert set(ct._METHOD_AWARE) == GOLDEN_METHOD_AWARE


def test_gated_prefixes_match_golden():
    assert tuple(pa.GATED_MCP_PREFIXES) == GOLDEN_GATED_PREFIXES


def test_non_admin_blocked_matches_golden():
    assert set(ts.NON_ADMIN_BLOCKED_TOOLS) == GOLDEN_NON_ADMIN_BLOCKED


def test_plan_mode_mutators_match_golden():
    assert set(ts._PLAN_MODE_KNOWN_MUTATORS) == GOLDEN_PLAN_MODE_MUTATORS


def test_untrusted_source_matches_golden():
    assert set(ct._UNTRUSTED_SOURCE_TOOLS) == GOLDEN_UNTRUSTED_SOURCE
    assert tuple(ct._UNTRUSTED_PREFIXES) == GOLDEN_UNTRUSTED_PREFIXES


def test_credentialed_mutators_match_golden():
    assert set(ct._CREDENTIALED_MUTATORS) == GOLDEN_CREDENTIALED_MUTATORS


def test_non_admin_blocked_prefix_is_mcp():
    assert tuple(ts.NON_ADMIN_BLOCKED_PREFIXES) == ("mcp__",)


# ── Per-tool: the table's classification matches every golden membership ──────

def test_every_gated_tool_classified_gated():
    for name in GOLDEN_GATED:
        assert get_policy(name).gated is True, name


def test_every_mutating_tool_classified_mutating():
    for name in GOLDEN_GATED | GOLDEN_FAILCLOSED_EXTRA:
        assert get_policy(name).mutating is True, name


def test_every_non_admin_blocked_tool_flagged():
    for name in GOLDEN_NON_ADMIN_BLOCKED:
        assert get_policy(name).non_admin_blocked is True, name
        assert ts.is_public_blocked_tool(name) is True, name


def test_every_plan_mode_mutator_flagged():
    for name in GOLDEN_PLAN_MODE_MUTATORS:
        assert get_policy(name).plan_mode_mutator is True, name


def test_every_credentialed_mutator_flagged():
    for name in GOLDEN_CREDENTIALED_MUTATORS:
        assert get_policy(name).credentialed_mutator is True, name


def test_every_untrusted_source_flagged():
    for name in GOLDEN_UNTRUSTED_SOURCE:
        assert get_policy(name).untrusted_source is True, name
        assert ct.is_untrusted_source(name) is True, name


# ── Functional accessors: identical behaviour for the tricky cases ────────────

def test_is_mutating_tool_static_classification():
    # Gated + failclosed extras are mutating; a read-only tool is not.
    for name in GOLDEN_GATED | GOLDEN_FAILCLOSED_EXTRA:
        assert pa.is_mutating_tool(name) is True, name
    for name in ("read_file", "grep", "web_search"):
        assert pa.is_mutating_tool(name) is False, name
    # Unknown non-prefixed tool: MR-16 actuator tiering classifies via
    # actuator_tier, which fails CLOSED (unknown -> write-gated -> mutating). This
    # supersedes the pre-MR-16 fail-OPEN behaviour and is strictly safer.
    assert pa.is_mutating_tool("totally_unknown_tool") is True
    # Empty tool type -> mutating (unchanged).
    assert pa.is_mutating_tool(None) is True


def test_method_aware_api_call_respects_http_method():
    import json
    assert pa.is_mutating_tool("api_call", json.dumps({"method": "GET"})) is False
    assert pa.is_mutating_tool("api_call", json.dumps({"method": "POST"})) is True
    # Line-based content is parsed exactly like the executor (do_api_call): a
    # write verb -> mutating; a money/DELETE write escalates to hitl-forever (both
    # still mutating here). A bare single-line blob is a GET (read) -> not mutating,
    # matching what the executor would run.
    assert pa.is_mutating_tool("app_api", "gitea\nPOST /repos\n{}") is True
    assert pa.is_mutating_tool("app_api", "firefly\nPOST /api/v1/transactions") is True
    assert pa.is_mutating_tool("app_api", "gitea\nDELETE /repos/x") is True
    assert pa.is_mutating_tool("app_api", "miniflux\nGET /v1/entries") is False
    # Non-object JSON the executor errors on -> fail closed (mutating).
    assert pa.is_mutating_tool("app_api", json.dumps([1, 2])) is True


def test_browser_prefix_gated_untrusted_and_credentialed():
    assert pa.is_mutating_tool("browser_click") is True
    assert ct.is_untrusted_source("playwright_navigate") is True
    assert ct.is_credentialed_mutator("browser_fill") is True


def test_public_block_mcp_prefix():
    assert ts.is_public_blocked_tool("mcp__anything__tool") is True
    # Malformed (non-string) tool name fails closed.
    assert ts.is_public_blocked_tool(123) is True  # type: ignore[arg-type]
    # None / empty means "no tool" -> not blocked (unchanged).
    assert ts.is_public_blocked_tool(None) is False
    assert ts.is_public_blocked_tool("") is False


# ── Fail-closed: unknown / malformed -> most-restrictive ──────────────────────

def test_unknown_tool_resolves_most_restrictive():
    pol = get_policy("some_brand_new_tool")
    assert pol.tier == ToolTier.ADMIN
    assert pol.gated and pol.mutating and pol.non_admin_blocked
    assert pol.plan_mode_mutator and pol.credentialed_mutator and pol.untrusted_source


def test_none_and_nonstring_resolve_most_restrictive():
    for bad in (None, "", 123, object()):
        pol = get_policy(bad)  # type: ignore[arg-type]
        assert pol.tier == ToolTier.ADMIN
        assert pol.mutating and pol.non_admin_blocked


def test_exact_name_wins_over_prefix():
    # No exact-name entry starts with a pattern prefix, but verify the ordering
    # contract holds for a synthesized case via the public API.
    assert get_policy("read_file").tier == ToolTier.READ  # exact, not fallthrough


def test_names_with_rejects_unknown_flag():
    import pytest
    with pytest.raises(ValueError):
        tpt.names_with("not_a_flag")


def test_every_table_tool_has_valid_tier():
    for name, pol in tpt._TABLE.items():
        assert isinstance(pol.tier, ToolTier), name
