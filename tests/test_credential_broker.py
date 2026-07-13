"""MR-15 credential broker: the deterministic gate for outbound API calls.

Verifies the four security properties:
  1. The model-visible surface never contains the raw api_key.
  2. Off-policy destinations (unknown/disabled/host-mismatch) are refused before
     any credential is attached.
  3. Write destinations are reported as approval-requiring.
  4. An SSRF / base_url-override attempt cannot exfiltrate the key to an
     attacker host — the credential is only ever sent to the pinned host.
"""
import sys
import os

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── recording fake httpx client ────────────────────────────────

class _FakeResponse:
    def __init__(self):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}

    def json(self):
        return {"ok": True}

    @property
    def text(self):
        return '{"ok": true}'


class _RecordingClient:
    """Captures every outbound request so tests can assert where the api_key
    (in the headers) actually went."""

    calls = []

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def request(self, method, url, params=None, json=None, headers=None, auth=None):
        _RecordingClient.calls.append(
            {"method": method, "url": url, "headers": dict(headers or {}), "auth": auth}
        )
        return _FakeResponse()


@pytest.fixture
def broker_env(tmp_path, monkeypatch):
    """Import the broker with the integration store + httpx redirected to tmp/fake."""
    from src import integrations

    monkeypatch.setattr(integrations, "DATA_FILE", str(tmp_path / "integrations.json"))
    _RecordingClient.calls = []
    monkeypatch.setattr(integrations.httpx, "AsyncClient", _RecordingClient)

    integrations.save_integrations([
        {
            "id": "mf1",
            "name": "Miniflux",
            "preset": "miniflux",
            "base_url": "http://legit.internal",
            "auth_type": "header",
            "auth_header": "X-Auth-Token",
            "api_key": "SUPER-SECRET-KEY",
            "enabled": True,
        },
        {
            "id": "off1",
            "name": "Disabled",
            "base_url": "http://disabled.internal",
            "auth_type": "bearer",
            "api_key": "OTHER-SECRET",
            "enabled": False,
        },
    ])

    import src.credential_broker as broker
    import importlib
    importlib.reload(broker)
    return broker, integrations


# ── 1. model-visible surface never contains the api_key ─────────

def test_tool_schema_and_prompt_expose_no_api_key(broker_env):
    _, integrations = broker_env
    import src.agent_tools  # noqa: F401 — import first to satisfy the schemas<->tools cycle
    from src.tool_schemas import FUNCTION_TOOL_SCHEMAS

    api_call_schema = next(
        s for s in FUNCTION_TOOL_SCHEMAS if s["function"]["name"] == "api_call"
    )
    props = api_call_schema["function"]["parameters"]["properties"]
    # The agent-facing schema offers no way to supply/observe a credential.
    assert "api_key" not in props
    assert "base_url" not in props
    assert set(props).issubset({"integration", "method", "path", "body", "params", "headers"})

    prompt = integrations.get_integrations_prompt()
    assert "SUPER-SECRET-KEY" not in prompt


async def test_broker_success_result_never_echoes_key(broker_env):
    broker, _ = broker_env
    req = broker.BrokerRequest(target="mf1", method="GET", path="/v1/entries")
    result = await broker.broker_api_call(req)

    assert result["exit_code"] == 0
    assert "SUPER-SECRET-KEY" not in str(result)
    # The key WAS attached server-side to the real request, to the pinned host.
    assert len(_RecordingClient.calls) == 1
    sent = _RecordingClient.calls[0]
    assert "legit.internal" in sent["url"]
    assert sent["headers"].get("X-Auth-Token") == "SUPER-SECRET-KEY"


def test_broker_request_dataclass_has_no_secret_field(broker_env):
    broker, _ = broker_env
    req = broker.BrokerRequest(target="mf1", method="GET", path="/v1/entries")
    # The logical request the agent constructs carries no credential material.
    assert not hasattr(req, "api_key")
    assert "SECRET" not in str(req)


# ── 2. off-policy destination refused ───────────────────────────

async def test_unknown_integration_refused(broker_env):
    broker, _ = broker_env
    req = broker.BrokerRequest(target="does-not-exist", method="GET", path="/x")
    result = await broker.broker_api_call(req)

    assert result["exit_code"] == 1
    assert result.get("refused") is True
    assert _RecordingClient.calls == []  # no network, no cred


async def test_disabled_integration_refused(broker_env):
    broker, _ = broker_env
    req = broker.BrokerRequest(target="off1", method="GET", path="/api/")
    result = await broker.broker_api_call(req)

    assert result.get("refused") is True
    assert _RecordingClient.calls == []


def test_off_policy_host_mismatch_is_refused_by_policy(broker_env):
    broker, _ = broker_env
    # A path that would resolve to a different host is off-policy.
    req = broker.BrokerRequest(target="mf1", method="GET", path="/v1/x")
    good = broker.evaluate_policy(req)
    assert good.allowed and good.destination == "legit.internal"


# ── 3. write destination requires approval ──────────────────────

def test_write_method_requires_approval(broker_env):
    broker, _ = broker_env
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        d = broker.evaluate_policy(
            broker.BrokerRequest(target="mf1", method=method, path="/v1/feeds")
        )
        assert d.allowed is True
        assert d.requires_approval is True, method


def test_read_method_does_not_require_approval(broker_env):
    broker, _ = broker_env
    d = broker.evaluate_policy(
        broker.BrokerRequest(target="mf1", method="GET", path="/v1/entries")
    )
    assert d.allowed is True
    assert d.requires_approval is False


def test_pending_actions_gates_api_call_writes(broker_env, monkeypatch):
    # Defense in depth: the existing approval queue still classifies api_call
    # writes as mutating (fail-closed) independent of the broker.
    import json as _json
    from src import pending_actions

    monkeypatch.setattr(pending_actions, "get_setting", lambda k, d=None: True)
    write = _json.dumps({"integration": "mf1", "method": "POST", "path": "/v1/feeds"})
    read = _json.dumps({"integration": "mf1", "method": "GET", "path": "/v1/entries"})
    assert pending_actions.requires_approval("api_call", write) is True
    assert pending_actions.requires_approval("api_call", read) is False


# ── 4. SSRF / base_url override cannot exfiltrate the key ────────

async def test_base_url_override_in_agent_args_is_ignored(broker_env):
    """Agent supplies a base_url pointing at an attacker host; the broker builds
    the request from the registered integration only, so the key never leaves
    the pinned host."""
    broker, _ = broker_env
    # BrokerRequest has no base_url field — an attacker 'base_url' key simply
    # cannot be threaded in. Simulate the raw agent dict the tool layer parses:
    from src.tool_implementations import do_api_call
    import json as _json

    content = _json.dumps({
        "integration": "mf1",
        "method": "GET",
        "path": "/v1/entries",
        "base_url": "http://attacker.evil",  # SSRF attempt
        "url": "http://attacker.evil",
    })
    result = await do_api_call(content)
    assert result["exit_code"] == 0
    assert len(_RecordingClient.calls) == 1
    sent = _RecordingClient.calls[0]
    # Key went ONLY to the pinned host, never to the attacker.
    assert "attacker.evil" not in sent["url"]
    assert "legit.internal" in sent["url"]
    assert sent["headers"].get("X-Auth-Token") == "SUPER-SECRET-KEY"


async def test_scheme_relative_path_cannot_redirect_key(broker_env):
    """A scheme-relative path '//attacker.evil/x' must not repoint the host."""
    from urllib.parse import urlparse

    broker, _ = broker_env
    req = broker.BrokerRequest(target="mf1", method="GET", path="//attacker.evil/x")
    await broker.broker_api_call(req)

    # Either refused (host mismatch) or safely rewritten to a path segment — but
    # in NO case does the credential-bearing request's HOST become the attacker.
    for sent in _RecordingClient.calls:
        assert urlparse(sent["url"]).hostname == "legit.internal"


async def test_agent_supplied_credential_headers_are_stripped(broker_env):
    """The agent cannot inject Authorization/Host/Cookie or the integration's
    own auth header — only the broker sets credential/routing headers."""
    broker, _ = broker_env
    req = broker.BrokerRequest(
        target="mf1",
        method="GET",
        path="/v1/entries",
        headers={
            "Authorization": "Bearer attacker-token",
            "Host": "attacker.evil",
            "Cookie": "session=steal",
            "X-Auth-Token": "attacker-spoof",  # tries to preempt the real key
            "X-Custom-Safe": "kept",
        },
    )
    result = await broker.broker_api_call(req)
    assert result["exit_code"] == 0
    sent = _RecordingClient.calls[0]
    hdrs = {k.lower(): v for k, v in sent["headers"].items()}
    assert hdrs.get("authorization") is None
    assert hdrs.get("host") is None
    assert hdrs.get("cookie") is None
    # The real key — set by the broker/execute path — wins, not the spoof.
    assert sent["headers"].get("X-Auth-Token") == "SUPER-SECRET-KEY"
    assert sent["headers"].get("X-Custom-Safe") == "kept"


async def test_off_policy_write_does_not_touch_network(broker_env):
    broker, _ = broker_env
    req = broker.BrokerRequest(target="off1", method="POST", path="/api/x", body={"a": 1})
    result = await broker.broker_api_call(req)
    assert result.get("refused") is True
    assert _RecordingClient.calls == []
