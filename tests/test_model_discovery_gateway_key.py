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


# ── auth_headers_for: the path the warmup/keepalive loop must use ────────────
#
# The probe path (_check_port) authenticated correctly from commit 1982e52, but
# the startup warmup and its 60s keepalive issued a bare httpx GET against the
# same /v1/models URL. That sent no credential, LiteLLM logged it as
# api_key='None', and it ran 1,442 times a day for two days.


def test_headers_returned_for_the_configured_gateway(gateway_env):
    md = ModelDiscovery(default_host="localhost")
    assert md.auth_headers_for("http://litellm:4000/v1/models") == {
        "Authorization": "Bearer sentinel-key"
    }


def test_headers_correct_before_get_hosts_has_run(gateway_env):
    """Warmup can ask for headers before any discovery pass has populated
    _auth_targets, so this must read the env rather than that instance state."""
    md = ModelDiscovery(default_host="localhost")
    assert md._auth_targets == set()          # _get_hosts() not yet called
    assert md.auth_headers_for("http://litellm:4000/v1/models")


def test_no_headers_for_a_scanned_host(gateway_env):
    md = ModelDiscovery(default_host="localhost")
    assert md.auth_headers_for("http://192.168.1.50:11434/v1/models") == {}


def test_no_headers_when_key_is_absent(gateway_env, monkeypatch):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    md = ModelDiscovery(default_host="localhost")
    assert md.auth_headers_for("http://litellm:4000/v1/models") == {}


def test_malformed_url_does_not_raise(gateway_env):
    md = ModelDiscovery(default_host="localhost")
    for bad in ("", "not-a-url", "http://litellm/v1/models"):   # last has no port
        assert md.auth_headers_for(bad) == {}


def test_scoping_matches_the_probe_path(gateway_env):
    """auth_headers_for and _check_port must agree on who gets the key.
    They disagreed once already, which is the whole bug."""
    md = ModelDiscovery(default_host="localhost")
    md._get_hosts()
    for host, port in md._auth_targets:
        assert md.auth_headers_for(f"http://{host}:{port}/v1/models")


# ── fingerprint caching: stop the /api/v1/models 404 every 60s ───────────────


def test_fingerprint_is_probed_once_then_cached(gateway_env, monkeypatch):
    calls = []

    def counting_probe(host, port):
        calls.append((host, port))
        return None

    md = ModelDiscovery(default_host="localhost")
    monkeypatch.setattr(md, "_probe_provider", counting_probe)
    for _ in range(5):
        md._fingerprint_provider("litellm", 4000)
    assert len(calls) == 1, f"probed {len(calls)}x; should be cached after the first"
