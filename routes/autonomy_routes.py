"""Kill-switch + circuit-breaker control API (Phase-4 autonomy safety).

Pairs with ``src/autonomy_guard.py``. The primary caller is a one-tap **ntfy
actionable notification**: the halt alert carries an ``http`` action that POSTs
to ``/api/autonomy/halt`` with an ``X-Autonomy-Token`` header, so the operator
can stop all autonomous action from their phone without opening the app.

Authorization accepts EITHER an authenticated app session (``require_user``) OR a
shared kill-token (constant-time compared against the ``autonomy_kill_token``
setting) for the headless ntfy path. If neither is present the request is
rejected — but note the halt itself is the *safe* direction, so we only guard it
to stop griefing, not to make stopping hard.
"""
from __future__ import annotations

import hmac
import logging

from fastapi import APIRouter, HTTPException, Request

from src import autonomy_guard as guard
from src.auth_helpers import get_current_user
from src.settings import get_setting

logger = logging.getLogger(__name__)


def _token_ok(request: Request) -> bool:
    """Constant-time compare of the X-Autonomy-Token header to the configured
    kill-token. Returns False when no token is configured (header path disabled)."""
    configured = get_setting("autonomy_kill_token", "") or ""
    supplied = request.headers.get("X-Autonomy-Token", "") or ""
    if not configured or not supplied:
        return False
    return hmac.compare_digest(str(configured), str(supplied))


def _authorize(request: Request) -> str:
    """Return the acting identity, or raise 401. Accepts a valid session user or a
    valid kill-token."""
    if _token_ok(request):
        return "ntfy-token"
    user = get_current_user(request)
    if user is not None:
        return user or "user"
    raise HTTPException(401, "authentication required")


def setup_autonomy_routes() -> APIRouter:
    router = APIRouter(prefix="/api/autonomy", tags=["autonomy"])

    @router.get("/status")
    async def status(request: Request):
        _authorize(request)
        return {
            "halt": guard.halt_status(),
            "autonomy_enabled": guard.autonomy_enabled(),
            "breakers": guard.breaker_status(),
        }

    @router.post("/halt")
    async def halt(request: Request):
        """Engage the global kill-switch. The safe direction — one tap stops
        every in-flight and future autonomous action."""
        actor = _authorize(request)
        reason = "kill-switch"
        try:
            body = await request.json()
            if isinstance(body, dict) and body.get("reason"):
                reason = str(body["reason"])[:500]
        except Exception:
            pass  # empty/non-JSON body is fine
        detail = guard.halt(reason=reason, source=f"api:{actor}")
        return {"ok": True, "halted": True, "detail": detail}

    @router.post("/resume")
    async def resume(request: Request):
        """Release the kill-switch. Deliberate operator action — token path is NOT
        accepted here so a leaked ntfy token can only STOP, never re-arm."""
        user = get_current_user(request)
        if user is None:
            raise HTTPException(401, "authenticated session required to resume autonomy")
        guard.resume()
        logger.warning("autonomy resumed by %s", user or "user")
        return {"ok": True, "halted": False}

    @router.post("/breakers/reset")
    async def reset_breakers(request: Request):
        _authorize(request)
        try:
            body = await request.json()
        except Exception:
            body = {}
        key = body.get("key") if isinstance(body, dict) else None
        if key:
            guard.reset(str(key))
        else:
            guard.reset_all()
        return {"ok": True, "breakers": guard.breaker_status()}

    return router
