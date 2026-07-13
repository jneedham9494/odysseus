"""MR-12 source summarizers — read-only Miniflux/Paperless agent tools.

Covers the two do_* handlers (summary content from mocked API responses,
the "no integration configured" path, and the read-only GET request shape)
plus correct registration in the schema / tag / index surfaces.

Network is fully mocked: `execute_api_call` and `load_integrations` are
patched, so the tools never touch httpx or disk.
"""
import asyncio
import json

import pytest

from src import tool_implementations as ti


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def _api_ok(payload) -> dict:
    """Shape an execute_api_call success result: HTTP status line + JSON body."""
    return {"output": "HTTP 200\n" + json.dumps(payload), "exit_code": 0}


class _Recorder:
    """Stand-in for execute_api_call that records the call and returns canned data."""

    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    async def __call__(self, integration_id, method, path, params=None,
                        body=None, extra_headers=None):
        self.calls.append({"id": integration_id, "method": method,
                           "path": path, "params": params, "body": body})
        return _api_ok(self.payload)


MINIFLUX_RESPONSE = {
    "total": 3,
    "entries": [
        {"id": 1, "title": "Rust 2.0 released",
         "feed": {"title": "This Week in Rust"}, "published_at": "2026-07-11T08:00:00Z"},
        {"id": 2, "title": "New CVE in OpenSSL",
         "feed": {"title": "Security Weekly"}, "published_at": "2026-07-10T12:30:00Z"},
        {"id": 3, "title": "Homelab GPU tuning",
         "feed": {"title": "Self-Hosted"}, "published_at": "2026-07-09T20:15:00Z"},
    ],
}

PAPERLESS_RESPONSE = {
    "count": 2,
    "results": [
        {"id": 42, "title": "Electricity bill June",
         "correspondent": {"name": "PowerCo"},
         "document_type": {"name": "Invoice"}, "created": "2026-07-08T00:00:00Z"},
        {"id": 41, "title": "Tenancy agreement",
         "correspondent": {"name": "Landlord Ltd"},
         "document_type": {"name": "Contract"}, "created": "2026-07-01T00:00:00Z"},
    ],
}


# ---------------------------------------------------------------------------
# Miniflux summarizer
# ---------------------------------------------------------------------------

def test_summarize_miniflux_unread_covers_all_items(monkeypatch):
    rec = _Recorder(MINIFLUX_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux",
                                  "name": "Miniflux", "enabled": True}])

    result = _run(ti.do_summarize_miniflux_unread("{}"))

    assert result["exit_code"] == 0
    assert result["count"] == 3
    assert result["total"] == 3
    summary = result["summary"]
    # Every entry title AND its feed appears in the summary.
    for entry in MINIFLUX_RESPONSE["entries"]:
        assert entry["title"] in summary
        assert entry["feed"]["title"] in summary
    assert "3 unread Miniflux entries" in summary


def test_summarize_miniflux_unread_issues_readonly_get(monkeypatch):
    rec = _Recorder(MINIFLUX_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux", "enabled": True}])

    _run(ti.do_summarize_miniflux_unread(json.dumps({"limit": 5})))

    assert len(rec.calls) == 1
    call = rec.calls[0]
    assert call["method"] == "GET"          # read-only: never a mutating verb
    assert call["path"] == "/v1/entries"
    assert call["params"]["status"] == "unread"
    assert call["params"]["limit"] == 5


def test_summarize_miniflux_unread_no_integration_returns_error(monkeypatch):
    monkeypatch.setattr("src.integrations.load_integrations", lambda: [])
    result = _run(ti.do_summarize_miniflux_unread("{}"))
    assert result["exit_code"] == 1
    assert "Miniflux" in result["error"]


def test_summarize_miniflux_unread_skips_disabled_integration(monkeypatch):
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux", "enabled": False}])
    result = _run(ti.do_summarize_miniflux_unread("{}"))
    assert result["exit_code"] == 1


# ---------------------------------------------------------------------------
# Paperless summarizer
# ---------------------------------------------------------------------------

def test_summarize_paperless_recent_covers_all_items(monkeypatch):
    rec = _Recorder(PAPERLESS_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "pl1", "preset": "paperless",
                                  "name": "Paperless", "enabled": True}])

    result = _run(ti.do_summarize_paperless_recent("{}"))

    assert result["exit_code"] == 0
    assert result["count"] == 2
    summary = result["summary"]
    for doc in PAPERLESS_RESPONSE["results"]:
        assert doc["title"] in summary
        assert doc["correspondent"]["name"] in summary
        assert doc["document_type"]["name"] in summary
    assert "2 recent Paperless documents" in summary


def test_summarize_paperless_recent_issues_readonly_get(monkeypatch):
    rec = _Recorder(PAPERLESS_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "pl1", "name": "paperless-ngx", "enabled": True}])

    _run(ti.do_summarize_paperless_recent(json.dumps({"limit": 3})))

    call = rec.calls[0]
    assert call["method"] == "GET"
    assert call["path"] == "/api/documents/"
    assert call["params"]["ordering"] == "-created"
    assert call["params"]["page_size"] == 3


def test_summarize_paperless_recent_no_integration_returns_error(monkeypatch):
    monkeypatch.setattr("src.integrations.load_integrations", lambda: [])
    result = _run(ti.do_summarize_paperless_recent("{}"))
    assert result["exit_code"] == 1
    assert "Paperless" in result["error"]


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------

def test_limit_is_clamped(monkeypatch):
    rec = _Recorder(MINIFLUX_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux", "enabled": True}])
    _run(ti.do_summarize_miniflux_unread(json.dumps({"limit": 9999})))
    assert rec.calls[0]["params"]["limit"] == 50  # clamped to hi bound


def test_upstream_error_is_propagated(monkeypatch):
    async def _boom(*a, **k):
        return {"error": "HTTP 500\nboom", "exit_code": 1}
    monkeypatch.setattr("src.integrations.execute_api_call", _boom)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux", "enabled": True}])
    result = _run(ti.do_summarize_miniflux_unread("{}"))
    assert result["exit_code"] == 1


# ---------------------------------------------------------------------------
# Registration: schema + tag + index
# ---------------------------------------------------------------------------

TOOL_NAMES = ("summarize_miniflux_unread", "summarize_paperless_recent")


def test_registered_in_function_schemas():
    # agent_tools/tool_parsing/tool_schemas form a circular cluster that only
    # resolves cleanly when entered via agent_tools (it re-exports the schemas).
    import src.agent_tools  # noqa: F401
    from src.agent_tools import FUNCTION_TOOL_SCHEMAS
    names = {s.get("function", {}).get("name") for s in FUNCTION_TOOL_SCHEMAS}
    for name in TOOL_NAMES:
        assert name in names, f"{name} missing from FUNCTION_TOOL_SCHEMAS"


def test_registered_in_tool_tags():
    from src.agent_tools import TOOL_TAGS
    for name in TOOL_NAMES:
        assert name in TOOL_TAGS, f"{name} missing from TOOL_TAGS"


def test_registered_in_tool_index_descriptions():
    from src.tool_index import BUILTIN_TOOL_DESCRIPTIONS
    for name in TOOL_NAMES:
        assert name in BUILTIN_TOOL_DESCRIPTIONS, f"{name} missing from tool index"
        assert BUILTIN_TOOL_DESCRIPTIONS[name].strip()


def test_read_only_not_in_mutator_lists():
    """Summarizers are reads: they must NOT be gated as mutators."""
    from src.tool_security import _PLAN_MODE_KNOWN_MUTATORS, PLAN_MODE_READONLY_TOOLS
    for name in TOOL_NAMES:
        assert name not in _PLAN_MODE_KNOWN_MUTATORS
        assert name in PLAN_MODE_READONLY_TOOLS


def test_summarizers_are_taint_sources():
    """They ingest attacker-controllable remote-feed/document text into context,
    so ingesting them must taint the session (same threat class as web_fetch).

    Without this, a malicious RSS item title / Paperless document could inject
    text that later auto-fires a credentialed action; the taint gate is what
    forces such an action through human approval instead.
    """
    import src.context_taint as ct
    for name in TOOL_NAMES:
        assert ct.is_untrusted_source(name), f"{name} must be a taint source"


def test_summarizers_taint_then_gate_credentialed_action():
    """End-to-end: after a summarizer read taints the session, a later
    credentialed mutator (send_email) is forced through approval."""
    import src.context_taint as ct
    sid = "sess-summarizer-taint"
    ct._TAINTED_SESSIONS.discard(sid)
    try:
        assert ct.requires_taint_approval(sid, "send_email") is False
        # The agent loop marks the session tainted for any untrusted source.
        for name in TOOL_NAMES:
            if ct.is_untrusted_source(name):
                ct.mark_tainted(sid)
        assert ct.is_tainted(sid)
        assert ct.requires_taint_approval(sid, "send_email") is True
    finally:
        ct._TAINTED_SESSIONS.discard(sid)


def test_summarizers_blocked_for_non_admin():
    """Both hit the admin-scoped integration surface, so a non-admin (like the
    api_call they wrap) must be blocked from reaching the owner's data."""
    from src.tool_security import NON_ADMIN_BLOCKED_TOOLS, is_public_blocked_tool
    for name in TOOL_NAMES:
        assert name in NON_ADMIN_BLOCKED_TOOLS, f"{name} must be non-admin blocked"
        assert is_public_blocked_tool(name) is True


def test_dispatch_routes_summarizers(monkeypatch):
    """execute_tool_block must reach the do_* handlers for these tool types."""
    from src.agent_tools import ToolBlock
    import src.tool_execution as te

    rec = _Recorder(MINIFLUX_RESPONSE)
    monkeypatch.setattr("src.integrations.execute_api_call", rec)
    monkeypatch.setattr("src.integrations.load_integrations",
                        lambda: [{"id": "mf1", "preset": "miniflux", "enabled": True}])
    # These tools are admin-scoped (in NON_ADMIN_BLOCKED_TOOLS); this test only
    # checks that dispatch reaches the handler, so run as an admin owner.
    monkeypatch.setattr(te, "_owner_is_admin", lambda owner: True)

    desc, result = _run(te.execute_tool_block(
        ToolBlock("summarize_miniflux_unread", "{}"), session_id=None, owner="admin"))
    assert result["exit_code"] == 0
    assert "Rust 2.0 released" in result["summary"]
