"""Approval-queue API: list / approve / reject pending agent actions.

Pairs with ``src/pending_actions.py`` and the approval gate in
``src/agent_loop.py``. Approving an action replays it through
``execute_tool_block`` server-side and records the result.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException

from src.auth_helpers import require_user
from src import pending_actions as pa
from src.tool_execution import execute_tool_block

logger = logging.getLogger(__name__)


def setup_pending_routes() -> APIRouter:
    router = APIRouter(prefix="/api/pending-actions", tags=["pending-actions"])

    @router.get("")
    async def list_actions(owner: str = Depends(require_user)):
        return {"pending": pa.list_pending(owner), "confirm_enabled": pa.confirm_enabled()}

    @router.post("/{pid}/approve")
    async def approve(pid: str, owner: str = Depends(require_user)):
        rec = pa.get(pid, owner=owner)
        if not rec:
            raise HTTPException(404, "pending action not found")
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
            raise HTTPException(500, f"execution failed: {e}")
        pa.mark(pid, "executed", json.dumps(result)[:8000])
        return {"ok": True, "id": pid, "tool_type": rec["tool_type"], "result": result}

    @router.post("/{pid}/reject")
    async def reject(pid: str, owner: str = Depends(require_user)):
        rec = pa.get(pid, owner=owner)
        if not rec:
            raise HTTPException(404, "pending action not found")
        pa.mark(pid, "rejected")
        return {"ok": True, "id": pid, "status": "rejected"}

    return router
