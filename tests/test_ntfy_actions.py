"""MR-10 ntfy action spine: a pending action produces a categorized ntfy push
with correct, token-scoped approve/reject http-action URLs, and an approve tap
maps back to the exact pending id. All HTTP is mocked -- tests run offline."""
from __future__ import annotations

import re

import pytest

from src import ntfy_actions as na


# ---------------------------------------------------------------------------
# Token spine: scoped to exactly (id, action)
# ---------------------------------------------------------------------------

def test_action_token_round_trips_for_same_id_and_action():
    tok = na.make_action_token("abc123", "approve")
    assert na.verify_action_token("abc123", "approve", tok) is True


def test_approve_token_does_not_authorize_a_different_pending_id():
    tok = na.make_action_token("pidA", "approve")
    # A leaked approve token for pidA must not approve pidB.
    assert na.verify_action_token("pidB", "approve", tok) is False


def test_approve_token_does_not_authorize_reject():
    tok = na.make_action_token("abc123", "approve")
    assert na.verify_action_token("abc123", "reject", tok) is False


def test_verify_rejects_garbage_token_without_raising():
    assert na.verify_action_token("abc123", "approve", "") is False
    assert na.verify_action_token("abc123", "approve", "deadbeef") is False
    assert na.verify_action_token("abc123", "approve", None) is False  # type: ignore[arg-type]


def test_make_token_rejects_unknown_action_and_bad_id():
    with pytest.raises(ValueError):
        na.make_action_token("abc123", "launch_missiles")
    with pytest.raises(ValueError):
        na.make_action_token("bad id with spaces!", "approve")


# ---------------------------------------------------------------------------
# Categorization
# ---------------------------------------------------------------------------

def test_categorize_flags_destructive_tools_urgent():
    priority, tags = na.categorize("bash")
    assert priority == "urgent"
    assert "warning" in tags


def test_categorize_defaults_for_unknown_tool():
    assert na.categorize("some_reader_tool") == ("high", "warning")


# ---------------------------------------------------------------------------
# Approval headers: correct approve/reject URLs carrying the pid + token
# ---------------------------------------------------------------------------

def _parse_actions(actions_header: str):
    """Return {label: url} for the http actions in an ntfy Actions header."""
    out = {}
    for chunk in actions_header.split(";"):
        parts = [p.strip() for p in chunk.split(",")]
        if parts and parts[0] == "http":
            out[parts[1]] = parts[2]
    return out


def test_build_approval_headers_has_scoped_approve_and_reject_urls():
    base = "https://assistant.example.ts.net"
    headers = na.build_approval_headers("deadbeef01", "bash", base)
    actions = _parse_actions(headers["Actions"])

    approve = actions["Approve"]
    reject = actions["Reject"]
    assert approve.startswith(f"{base}/api/pending-actions/deadbeef01/approve?token=")
    assert reject.startswith(f"{base}/api/pending-actions/deadbeef01/reject?token=")

    # The embedded tokens verify only for their own (id, action).
    atok = approve.split("token=")[1]
    rtok = reject.split("token=")[1]
    assert na.verify_action_token("deadbeef01", "approve", atok) is True
    assert na.verify_action_token("deadbeef01", "reject", rtok) is True
    assert na.verify_action_token("deadbeef01", "approve", rtok) is False


def test_build_approval_headers_categorizes_destructive_action():
    headers = na.build_approval_headers("deadbeef01", "delete_file", "https://x.example")
    assert headers["Priority"] == "urgent"
    assert headers["Title"] == "Assistant action needs approval"


def test_build_approval_headers_requires_base_url():
    with pytest.raises(ValueError):
        na.build_approval_headers("deadbeef01", "bash", "")


def test_kill_switch_headers_carry_one_signed_stop_action():
    headers = na.build_kill_switch_headers("https://x.example")
    assert headers["Priority"] == "urgent"
    assert "http, STOP agent," in headers["Actions"]
    url = headers["Actions"].split(", ")[2].split(",")[0]
    token = url.split("token=")[1]
    assert na.verify_action_token("global", "kill", token) is True


# ---------------------------------------------------------------------------
# pending_actions._notify: the queued action emits the ntfy push (HTTP mocked)
# ---------------------------------------------------------------------------

class _Capture:
    def __init__(self):
        self.req = None

    def __call__(self, req, timeout=None):  # matches urllib.request.urlopen
        self.req = req

        class _Resp:
            def read(self_inner):
                return b""

        return _Resp()


def _install_ntfy(monkeypatch, base="https://assistant.example.ts.net"):
    import src.pending_actions as pa

    settings = {"agent_tool_confirm_ntfy": "https://ntfy.example/mytopic",
                "app_base_url": base}
    monkeypatch.setattr(pa, "get_setting",
                        lambda key, default=None: settings.get(key, default))
    cap = _Capture()
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", cap)
    return pa, cap


def test_notify_emits_approve_reject_urls_for_the_pid(monkeypatch):
    pa, cap = _install_ntfy(monkeypatch)
    pa._notify("cafebabe22", "bash: rm -rf /tmp/x", "bash")

    assert cap.req is not None
    assert cap.req.full_url == "https://ntfy.example/mytopic"
    actions = _parse_actions(cap.req.headers["Actions"])
    assert "/api/pending-actions/cafebabe22/approve?token=" in actions["Approve"]
    assert "/api/pending-actions/cafebabe22/reject?token=" in actions["Reject"]
    assert cap.req.headers["Priority"] == "urgent"  # bash is destructive


def test_notify_without_base_url_degrades_to_plain_alert(monkeypatch):
    pa, cap = _install_ntfy(monkeypatch, base="")
    pa._notify("cafebabe22", "bash: ls", "bash")

    assert "Actions" not in cap.req.headers
    assert cap.req.headers["Title"] == "Assistant action needs approval"


def test_notify_noop_when_topic_unset(monkeypatch):
    import src.pending_actions as pa
    monkeypatch.setattr(pa, "get_setting", lambda key, default=None: default)
    cap = _Capture()
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", cap)
    pa._notify("cafebabe22", "bash: ls", "bash")
    assert cap.req is None  # nothing sent


# ---------------------------------------------------------------------------
# End-to-end: the approve URL's pid resolves to the exact stashed record
# ---------------------------------------------------------------------------

def test_approve_url_pid_maps_back_to_the_stashed_pending_action(monkeypatch, tmp_path):
    import src.pending_actions as pa

    # Point the queue DB at a temp file and (re)create its schema.
    monkeypatch.setattr(pa, "PENDING_DB", str(tmp_path / "pending.db"))
    pa._init()

    pa, cap = _install_ntfy(monkeypatch)
    pid = pa.stash("jack", "sess-1", "bash", "rm -rf /tmp/x", workspace="ws")

    # Extract the pid the ntfy Approve button would hit.
    actions = _parse_actions(cap.req.headers["Actions"])
    m = re.search(r"/pending-actions/([^/]+)/approve", actions["Approve"])
    url_pid = m.group(1)

    assert url_pid == pid
    rec = pa.get(url_pid, owner="jack")
    assert rec is not None
    assert rec["tool_type"] == "bash"
    assert rec["content"] == "rm -rf /tmp/x"


# ---------------------------------------------------------------------------
# Route authorization: a signed button token authorizes exactly its own action
# ---------------------------------------------------------------------------

class _FakeRequest:
    """Stand-in used only to prove the token path never touches session auth."""


def test_route_authorize_accepts_valid_token_as_record_owner(monkeypatch):
    import routes.pending_routes as pr

    monkeypatch.setattr(pr.pa, "get", lambda pid, owner=None: {"owner": "jack"})
    tok = na.make_action_token("pid-1", "approve")
    assert pr._authorize(_FakeRequest(), "pid-1", "approve", tok) == "jack"


def test_route_authorize_rejects_token_minted_for_another_pending_id(monkeypatch):
    import routes.pending_routes as pr
    from fastapi import HTTPException

    tok = na.make_action_token("pid-1", "approve")
    with pytest.raises(HTTPException) as exc:
        pr._authorize(_FakeRequest(), "pid-2", "approve", tok)
    assert exc.value.status_code == 403
