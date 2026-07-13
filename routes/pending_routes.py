"""Approval-queue API: list / approve / reject pending agent actions.

Pairs with ``src/pending_actions.py`` and the approval gate in
``src/agent_loop.py``. Approving an action replays it through
``execute_tool_block`` server-side and records the result.

The core approve/reject logic lives in the module-level ``approve_pending`` /
``reject_pending`` coroutines so alternative front-ends (e.g. the Telegram bot
in ``src/telegram_bot.py``) can drive the SAME approval path instead of opening
a side door around the boundary. The HTTP handlers are thin wrappers that map
the structured result to HTTP status codes.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException

from src.auth_helpers import require_user
from src import pending_actions as pa
from src.tool_execution import execute_tool_block

logger = logging.getLogger(__name__)


async def approve_pending(pid: str, owner: Optional[str]) -> Dict[str, Any]:
    """Approve and execute a pending action, owner-scoped.

    Returns a structured result dict (never raises for the expected
    not-found / already-decided / execution-failed cases):
      - {"ok": True, "id", "tool_type", "result"}                 on success
      - {"ok": False, "error": "not_found"}                       unknown/foreign pid
      - {"ok": False, "status": <status>, "message": ...}         already decided
      - {"ok": False, "error": "execution_failed", "detail": ...} replay raised
    """
    rec = pa.get(pid, owner=owner)
    if not rec:
        return {"ok": False, "error": "not_found"}
    if rec.get("status") != "pending":
        return {"ok": False, "status": rec.get("status"), "message": "already decided"}
    block = pa.ReplayBlock(rec["tool_type"], rec["content"])
    try:
        _desc, result = await execute_tool_block(
            block,
            session_id=rec.get("session_id") or None,
            owner=owner,
            workspace=rec.get("workspace") or None,
        )
    except Exception as e:  # pragma: no cover - defensive
        logger.exception("approved action %s failed to execute", pid)
        pa.mark(pid, "failed", json.dumps({"error": str(e)}))
        return {"ok": False, "error": "execution_failed", "detail": str(e)}
    pa.mark(pid, "executed", json.dumps(result)[:8000])
    return {"ok": True, "id": pid, "tool_type": rec["tool_type"], "result": result}


async def reject_pending(pid: str, owner: Optional[str]) -> Dict[str, Any]:
    """Reject a pending action, owner-scoped. Returns a structured result dict."""
    rec = pa.get(pid, owner=owner)
    if not rec:
        return {"ok": False, "error": "not_found"}
    pa.mark(pid, "rejected")
    return {"ok": True, "id": pid, "status": "rejected"}


def setup_pending_routes() -> APIRouter:
    router = APIRouter(prefix="/api/pending-actions", tags=["pending-actions"])

    @router.get("")
    async def list_actions(owner: str = Depends(require_user)):
        return {"pending": pa.list_pending(owner), "confirm_enabled": pa.confirm_enabled()}

    @router.post("/{pid}/approve")
    async def approve(pid: str, owner: str = Depends(require_user)):
        res = await approve_pending(pid, owner)
        if res.get("error") == "not_found":
            raise HTTPException(404, "pending action not found")
        if res.get("error") == "execution_failed":
            raise HTTPException(500, f"execution failed: {res.get('detail')}")
        return res

    @router.post("/{pid}/reject")
    async def reject(pid: str, owner: str = Depends(require_user)):
        res = await reject_pending(pid, owner)
        if res.get("error") == "not_found":
            raise HTTPException(404, "pending action not found")
        return res

    return router
