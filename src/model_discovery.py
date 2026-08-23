import subprocess
import json
import time
import httpx
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Env vars holding the API key for an authenticated model gateway (e.g. LiteLLM).
# The key is sent ONLY to the endpoint named by OLLAMA_BASE_URL / OLLAMA_URL /
# LM_STUDIO_URL - never to hosts turned up by the Tailscale/port scan, which
# would broadcast the credential to whatever happens to answer on the LAN.
_GATEWAY_KEY_ENVS = ("LITELLM_API_KEY", "MODEL_GATEWAY_API_KEY")

# Env vars that name a *configured* endpoint, as opposed to a host turned up by
# the Tailscale/port scan. Only these may receive the gateway key.
_ENDPOINT_ENVS = ("OLLAMA_BASE_URL", "OLLAMA_URL", "LM_STUDIO_URL")

# How long a provider fingerprint is trusted. Without this the LM Studio probe
# re-runs on every discovery pass, and against a gateway that has no such route
# it is a 404 a minute, forever.
_FINGERPRINT_TTL = 3600.0


def _configured_auth_targets() -> set:
    """(host, port) pairs from env config that may receive the gateway key.

    Single source of truth for the scoping rule, so the probe path and the
    warmup/keepalive path cannot drift apart - they did, and the result was a
    rejected request a minute for two days.
    """
    targets = set()
    for env_name in _ENDPOINT_ENVS:
        raw = os.getenv(env_name, "").strip()
        if not raw:
            continue
        try:
            parsed = urlparse(raw if "://" in raw else "http://" + raw)
        except Exception:
            continue
        if parsed.hostname and parsed.port:
            targets.add((parsed.hostname, parsed.port))
    return targets


def _gateway_api_key() -> str:
    for name in _GATEWAY_KEY_ENVS:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


# Cache for discovered hosts
_hosts_cache: List[str] = []
_hosts_cache_time: float = 0
_HOSTS_CACHE_TTL = 60  # seconds


def _parse_tailscale_status(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _first_tailscale_ipv4(value: Any) -> Optional[str]:
    if not isinstance(value, list):
        return None
    for ip in value:
        if isinstance(ip, str) and "." in ip:
            return ip
    return None


def discover_tailscale_hosts() -> List[str]:
    """Discover online Tailscale peers, returning their IPv4 addresses."""
    global _hosts_cache, _hosts_cache_time

    now = time.time()
    if _hosts_cache and (now - _hosts_cache_time) < _HOSTS_CACHE_TTL:
        return list(_hosts_cache)

    hosts = []
    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"], capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0:
            return hosts

        data = _parse_tailscale_status(result.stdout)
        if not data:
            return hosts

        # Add self
        self_data = data.get("Self") if isinstance(data.get("Self"), dict) else {}
        self_ip = _first_tailscale_ipv4(self_data.get("TailscaleIPs"))
        if self_ip:
            hosts.append(self_ip)

        # Add online peers (skip funnel-ingress-nodes and android devices)
        peers = data.get("Peer") if isinstance(data.get("Peer"), dict) else {}
        for peer in peers.values():
            if not isinstance(peer, dict):
                continue
            if not peer.get("Online"):
                continue
            hostname = peer.get("HostName", "")
            if hostname == "funnel-ingress-node":
                continue
            os_name = peer.get("OS", "")
            if os_name == "android":
                continue
            peer_ip = _first_tailscale_ipv4(peer.get("TailscaleIPs"))
            if peer_ip:
                hosts.append(peer_ip)

        _hosts_cache = hosts
        _hosts_cache_time = now
        logger.info(f"Tailscale discovery found {len(hosts)} hosts: {hosts}")
    except FileNotFoundError:
        logger.debug("tailscale command not found")
    except Exception as e:
        logger.warning(f"Tailscale discovery failed: {e}")

    return hosts


class ModelDiscovery:
    def __init__(self, default_host: str, openai_api_key: Optional[str] = None):
        self.default_host = default_host
        self.openai_api_key = openai_api_key
        self.openai_compat_path = "/v1/chat/completions"
        # Custom ports from env vars, merged into the scan list by discover_models.
        self._extra_ports: set = set()
        # (host, port) pairs from env config that may receive the gateway key.
        self._auth_targets: set = set()

    def _get_hosts(self) -> List[str]:
        """Get all hosts to scan, using env override, Tailscale, or default."""
        self._extra_ports = set()
        self._auth_targets = _configured_auth_targets()

        def _append_host(out: List[str], host: str) -> None:
            host = (host or "").strip()
            if not host or host in out:
                return
            out.append(host)

        def _append_env_hosts(out: List[str]) -> None:
            """Add hosts (and any custom ports) from provider-specific env vars."""
            for env_name in _ENDPOINT_ENVS:
                raw = os.getenv(env_name, "").strip()
                if not raw:
                    continue
                try:
                    parsed = urlparse(raw if "://" in raw else "http://" + raw)
                    _append_host(out, parsed.hostname or "")
                    if parsed.port:
                        self._extra_ports.add(parsed.port)
                except Exception:
                    pass

        # Manual override takes priority
        extra = os.getenv("LLM_HOSTS", "").strip()
        if extra:
            hosts = [h.strip() for h in extra.split(",") if h.strip()]
            # Always include the default host too
            if self.default_host not in hosts:
                hosts.insert(0, self.default_host)
            _append_host(hosts, "host.docker.internal")
            _append_env_hosts(hosts)
            return hosts

        # Try Tailscale discovery
        ts_hosts = discover_tailscale_hosts()
        if ts_hosts:
            # Ensure default_host is included
            if self.default_host not in ts_hosts:
                ts_hosts.insert(0, self.default_host)
            _append_host(ts_hosts, "host.docker.internal")
            _append_env_hosts(ts_hosts)
            return ts_hosts

        hosts = [self.default_host]
        # Docker desktop/Linux compose maps this to the host machine. That is
        # the common "I started Ollama normally on this computer" case.
        _append_host(hosts, "host.docker.internal")
        _append_env_hosts(hosts)
        return hosts

    def auth_headers_for(self, url: str) -> Dict[str, str]:
        """Auth headers for a probe ``url``, or ``{}`` if it is not a gateway.

        Same scoping rule as ``_check_port``: the key goes only to a host named
        by the endpoint env vars, never to one found by the scan. Callers
        outside discovery (startup warmup, keepalive) must route through this
        rather than issuing a bare request, or they authenticate as nobody.

        Reads the env directly rather than ``self._auth_targets`` so it is
        correct before ``_get_hosts()`` has ever run.
        """
        try:
            parsed = urlparse(url or "")
        except Exception:
            return {}
        if not parsed.hostname or not parsed.port:
            return {}
        if (parsed.hostname, parsed.port) not in _configured_auth_targets():
            return {}
        key = _gateway_api_key()
        return {"Authorization": f"Bearer {key}"} if key else {}

    def _fp_cache(self) -> Dict[Any, Any]:
        return self.__dict__.setdefault("_fingerprint_cache", {})

    def _fingerprint_provider(self, host: str, port: int) -> Optional[str]:
        """Identify the server software via its native API, independent of port."""
        cache = self._fp_cache()
        hit = cache.get((host, port))
        if hit is not None and (time.time() - hit[1]) < _FINGERPRINT_TTL:
            return hit[0]
        result = self._probe_provider(host, port)
        cache[(host, port)] = (result, time.time())
        return result

    def _probe_provider(self, host: str, port: int) -> Optional[str]:
        """Uncached native-API fingerprint. Only LM Studio answers this route."""
        try:
            r = httpx.get(f"http://{host}:{port}/api/v1/models", timeout=1.5)
            if r.is_success:
                models = (r.json() or {}).get("models")
                if (
                    isinstance(models, list)
                    and models
                    and isinstance(models[0], dict)
                    and "key" in models[0]
                    and "architecture" in models[0]
                ):
                    return "lmstudio"
        except Exception:
            pass
        return None

    def _check_port(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Check a single host:port for models."""
        base = f"http://{host}:{port}/v1"
        configured = (host, port) in self._auth_targets
        headers = {}
        if configured:
            key = _gateway_api_key()
            if key:
                headers["Authorization"] = f"Bearer {key}"
        try:
            # Only pass headers when there is actually a key, so the common
            # unauthenticated probe keeps its original call signature.
            kwargs = {"timeout": 3}
            if headers:
                kwargs["headers"] = headers
            r = httpx.get(f"{base}/models", **kwargs)
            if not r.is_success:
                if configured and r.status_code in (401, 403):
                    logger.warning(
                        "Model gateway %s:%s rejected discovery with HTTP %s. Set %s to a "
                        "valid key, or model discovery will report no models there.",
                        host, port, r.status_code, " or ".join(_GATEWAY_KEY_ENVS),
                    )
                return None
            data = r.json() or {}
            ids = [m.get("id") for m in (data.get("data") or []) if m.get("id")]
            if ids:
                return {
                    "host": host,
                    "port": port,
                    "url": f"http://{host}:{port}{self.openai_compat_path}",
                    "models": ids,
                    "models_display": [i.lstrip("/") for i in ids],
                    "provider": self._fingerprint_provider(host, port),
                }
        except Exception:
            pass
        return None

    def discover_models(self) -> Dict[str, List[Dict[str, Any]]]:
        """Discover available models from all reachable hosts."""
        hosts = self._get_hosts()
        items = []

        logger.info(f"Scanning {len(hosts)} hosts for models: {hosts}")

        # Well-known ports: 8000-8020 (vLLM, llama.cpp, SGLang, Cookbook),
        # 1234 (LM Studio), 11434 (Ollama), 11435 for APFEL as its default port is
        # occupied by Ollama. The env vars can add more ports which will be merged in.
        ports = list(range(8000, 8021)) + [1234, 11434, 11435]
        ports += [p for p in sorted(self._extra_ports) if p not in ports]
        targets = [(h, p) for h in hosts for p in ports]

        seen_models = (
            set()
        )  # dedupe by (port, model_ids) to avoid same machine via different IPs

        with ThreadPoolExecutor(max_workers=50) as pool:
            futures = {pool.submit(self._check_port, h, p): (h, p) for h, p in targets}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    key = (result["port"], tuple(sorted(result["models"])))
                    if key not in seen_models:
                        seen_models.add(key)
                        items.append(result)

        # Sort by host then port for consistent ordering
        items.sort(key=lambda x: (x["host"], x["port"]))

        logger.info(
            f"Discovered {len(items)} model endpoints across {len(hosts)} hosts"
        )
        return {"hosts": hosts, "items": items}

    def warmup_ping_urls(self, limit: int = 5) -> List[str]:
        """The ``/models`` URLs of up to ``limit`` discovered endpoints.

        Used by the startup warmup / keepalive loop to prime connections. Each
        discovered item already carries a ``/v1/chat/completions`` url; swap the
        suffix for the cheap ``/models`` probe. Failures degrade to an empty list
        so warmup never crashes the caller.
        """
        try:
            items = (self.discover_models() or {}).get("items", [])
        except Exception:
            return []
        urls: List[str] = []
        for ep in items[:limit]:
            url = (ep.get("url") or "").replace("/chat/completions", "/models")
            if url:
                urls.append(url)
        return urls

    def get_providers(self) -> Dict[str, Any]:
        """Get all available providers"""
        discovery = self.discover_models()
        items = discovery["items"]
        providers = [{"provider": "vllm", "hosts": discovery["hosts"], "items": items}]

        if self.openai_api_key:
            openai_models = [
                "gpt-5.2-codex",
                "gpt-4o-mini",
                "gpt-image-1.5",
                "gpt-4o",
                "gpt-5.2",
                "gpt-5.2-pro",
            ]
            providers.append(
                {
                    "provider": "openai",
                    "items": [
                        {
                            "url": "https://api.openai.com/v1/chat/completions",
                            "models": openai_models,
                        }
                    ],
                }
            )

        return {"providers": providers}
