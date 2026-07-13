"""Deterministic credential broker for outbound API-integration calls (MR-15).

Security control: the LLM must NEVER see a raw integration secret, and the
decision to attach a credential must be gated on the *destination* (which host
the request actually reaches) rather than on an agent-chosen verb or name.

This module is the single sanctioned entry point the agent path
(``do_api_call``) uses to reach ``integrations.execute_api_call``. It:

    (a) resolves credentials server-side only — the secret never enters the
        model-visible request/response surface;
    (b) evaluates a destination policy and REFUSES off-policy destinations
        (unknown/disabled integration, malformed target, or a request whose
        *resolved* host differs from the integration's registered host —
        an SSRF / host-override exfiltration attempt);
    (c) sanitizes agent-supplied headers so the agent can neither observe nor
        spoof credential/routing headers, then delegates the actual credential
        attachment to ``execute_api_call``.

Fail-closed: any resolution/validation error is a REFUSAL, never a silent
pass-through. Write methods are reported as approval-requiring so the existing
human approval queue (``src/pending_actions.py``) stays authoritative.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from src.integrations import (
    _find_integration,
    _join_integration_url,
    _normalize_integration_base_url,
    execute_api_call,
)

log = logging.getLogger(__name__)

# Verbs that mutate the destination. Gating is on destination, but the verb
# still classifies read vs. write for the approval requirement.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Agent-supplied headers that could carry or spoof credentials, or re-route the
# request to another host, are always stripped. The broker — not the model —
# owns auth and routing. Compared case-insensitively.
_BLOCKED_AGENT_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "host",
    "x-auth-token",
    "x-api-key",
    "x-forwarded-host",
    "x-forwarded-for",
    "forwarded",
})

# Same base_url path-suffix stripping that execute_api_call applies, replicated
# here so the broker computes the identical destination host it will call.
_STRIP_SUFFIXES: Dict[str, list] = {
    "miniflux": ["/v1"],
    "gitea": ["/api/v1", "/api"],
    "linkding": ["/api"],
    "homeassistant": ["/api"],
}


@dataclass(frozen=True)
class BrokerRequest:
    """A logical, credential-free outbound request as the agent expresses it.

    The agent supplies only a logical *target* (integration name or id) plus the
    method/path/params/body. It never supplies a base URL, host, or secret; any
    such fields are ignored by construction (they are not attributes here).
    """

    target: str
    method: str
    path: str
    params: Optional[Dict[str, Any]] = None
    body: Optional[Any] = None
    headers: Dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyDecision:
    """Result of evaluating the destination policy for a request."""

    allowed: bool
    requires_approval: bool
    destination: str  # resolved host, or "" when unresolved
    reason: str


def _strip_base_suffix(base_url: str, integration: Dict[str, Any]) -> str:
    """Apply the same preset path-suffix stripping execute_api_call uses."""
    preset = (integration.get("preset") or integration.get("name", "")).lower()
    for suf in _STRIP_SUFFIXES.get(preset, []):
        if base_url.endswith(suf):
            return base_url[: -len(suf)]
    return base_url


def _validate_path(path: str) -> Optional[str]:
    """Return a refusal reason if the path is unsafe, else None."""
    if not isinstance(path, str) or not path.startswith("/"):
        return "Path must start with /"
    if "://" in path:
        return "Path must not contain a protocol scheme"
    if "#" in path:
        return "Path must not contain a fragment"
    return None


def evaluate_policy(request: BrokerRequest) -> PolicyDecision:
    """Evaluate the destination policy for a request WITHOUT touching secrets.

    Refuses when the integration is unknown/disabled, the base URL is malformed,
    the path is unsafe, or the request's *resolved* host differs from the
    integration's registered host (host-override / SSRF). Otherwise allows, and
    flags write methods as approval-requiring.
    """
    target = request.target if isinstance(request.target, str) else ""
    integration = _find_integration(target)
    if not integration:
        return PolicyDecision(False, False, "", f"Unknown integration target: {target!r}")
    if not integration.get("enabled", True):
        return PolicyDecision(
            False, False, "", f"Integration '{integration.get('name')}' is disabled"
        )

    try:
        base_url = _normalize_integration_base_url(integration.get("base_url", ""))
    except ValueError as exc:
        return PolicyDecision(False, False, "", str(exc))

    registered_host = (urlparse(base_url).hostname or "").lower()
    if not registered_host:
        return PolicyDecision(False, False, "", "Integration base URL has no host")

    path_error = _validate_path(request.path)
    if path_error:
        return PolicyDecision(False, False, registered_host, path_error)

    # Host-pinning: compute the destination host exactly as the request would
    # reach it (base + path). If it is anything other than the registered host,
    # the request is off-policy — refuse before any credential is attached.
    resolved_base = _strip_base_suffix(base_url, integration)
    final_url = _join_integration_url(resolved_base, request.path)
    final_host = (urlparse(final_url).hostname or "").lower()
    if final_host != registered_host:
        return PolicyDecision(
            False,
            False,
            registered_host,
            f"Off-policy destination: request resolves to {final_host!r}, "
            f"integration is pinned to {registered_host!r}",
        )

    method = (request.method or "GET").upper()
    requires_approval = method in WRITE_METHODS
    return PolicyDecision(True, requires_approval, registered_host, "on-policy")


def _sanitize_agent_headers(
    headers: Optional[Dict[str, str]], integration: Dict[str, Any]
) -> Dict[str, str]:
    """Drop any agent header that could carry/spoof a credential or re-route.

    The integration's own auth header name is also stripped so the agent cannot
    pre-seed or observe it; only the broker (via execute_api_call) sets it.
    """
    if not headers or not isinstance(headers, dict):
        return {}
    blocked = set(_BLOCKED_AGENT_HEADERS)
    auth_header = str(integration.get("auth_header") or "").strip().lower()
    if auth_header:
        blocked.add(auth_header)
    clean: Dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str):
            continue
        if name.strip().lower() in blocked:
            log.warning("credential_broker: dropped agent-supplied header %r", name)
            continue
        clean[name] = value
    return clean


async def broker_api_call(request: BrokerRequest) -> Dict[str, Any]:
    """Sole credentialed path for agent-originated API-integration calls.

    Enforces the destination policy, sanitizes agent headers, then delegates to
    ``execute_api_call`` which attaches the server-side credential. On any policy
    refusal the request is dropped WITHOUT contacting the network or attaching a
    credential, so a secret can never be exfiltrated to an off-policy host.
    """
    decision = evaluate_policy(request)
    if not decision.allowed:
        log.warning("credential_broker refused request: %s", decision.reason)
        return {"error": f"Refused by credential broker: {decision.reason}",
                "exit_code": 1, "refused": True}

    integration = _find_integration(request.target)
    # evaluate_policy already confirmed the integration resolves; guard anyway.
    if not integration:
        return {"error": "Refused by credential broker: integration vanished",
                "exit_code": 1, "refused": True}

    safe_headers = _sanitize_agent_headers(request.headers, integration)
    return await execute_api_call(
        integration["id"],
        request.method,
        request.path,
        params=request.params,
        body=request.body,
        extra_headers=safe_headers or None,
    )
