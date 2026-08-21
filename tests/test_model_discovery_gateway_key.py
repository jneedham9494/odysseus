"""Discovery must authenticate to a gateway without leaking the key to the LAN.

OLLAMA_BASE_URL now points at the LiteLLM gateway, which requires a key. The
key may only be sent to that configured host: discovery also probes hosts found
by Tailscale enumeration and a wide port scan, and attaching the credential to
those would hand it to whatever happens to answer.
"""
import httpx
import pytest

from src.model_discovery import ModelDiscovery


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.is_success = 200 <= status < 300

    def json(self):
        return self._payload


@pytest.fixture
def gateway_env(monkeypatch):
    monkeypatch.delenv("LLM_HOSTS", raising=False)
    monkeypatch.delenv("OLLAMA_URL", raising=False)
    monkeypatch.delenv("LM_STUDIO_URL", raising=False)
    monkeypatch.delenv("MODEL_GATEWAY_API_KEY", raising=False)
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sentinel-key")


def _record(monkeypatch, status=200):
    seen = {}

    def fake_get(url, timeout=None, headers=None):
        seen[url] = headers
        return _Resp({"data": [{"id": "qwen3-coder:30b"}]}, status)

    monkeypatch.setattr("src.model_discovery.httpx.get", fake_get)
    return seen


def test_key_sent_to_configured_gateway(gateway_env, monkeypatch):
    d = ModelDiscovery(default_host="localhost")
    d._get_hosts()
    seen = _record(monkeypatch)

    assert d._check_port("litellm", 4000) is not None
    assert seen["http://litellm:4000/v1/models"] == {"Authorization": "Bearer sentinel-key"}


def test_key_never_sent_to_scanned_hosts(gateway_env, monkeypatch):
    d = ModelDiscovery(default_host="localhost")
    d._get_hosts()
    seen = _record(monkeypatch)

    d._check_port("192.168.1.50", 11434)
    d._check_port("some-tailnet-box", 8000)

    for url, headers in seen.items():
        assert not headers, f"credential leaked to {url}"


def test_unauthenticated_probe_keeps_original_signature(gateway_env, monkeypatch):
    """A probe with no key must not pass headers at all."""
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    d = ModelDiscovery(default_host="localhost")
    d._get_hosts()

    def strict_get(url, timeout=None):  # no headers kwarg
        return _Resp({"data": [{"id": "m"}]})

    monkeypatch.setattr("src.model_discovery.httpx.get", strict_get)
    assert d._check_port("litellm", 4000) is not None


def test_gateway_rejection_is_logged_loudly(gateway_env, monkeypatch, caplog):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    d = ModelDiscovery(default_host="localhost")
    d._get_hosts()
    _record(monkeypatch, status=401)

    with caplog.at_level("WARNING"):
        assert d._check_port("litellm", 4000) is None
    assert "LITELLM_API_KEY" in caplog.text


def test_scanned_host_rejection_is_not_logged(gateway_env, monkeypatch, caplog):
    """A 401 from a random scanned host is noise, not a misconfiguration."""
    d = ModelDiscovery(default_host="localhost")
    d._get_hosts()
    _record(monkeypatch, status=401)

    with caplog.at_level("WARNING"):
        d._check_port("192.168.1.50", 11434)
    assert "LITELLM_API_KEY" not in caplog.text
