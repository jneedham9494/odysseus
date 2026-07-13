"""Phase-4 autonomy safety gate: global kill-switch + circuit-breaker composition.

SAFE-BY-DEFAULT, OFF-BY-DEFAULT. This is the enforced gate every *self-initiated*
(autonomous) action must pass before executing. It NEVER weakens the existing
approval queue (``src/pending_actions.py``) or taint gate (``src/context_taint.py``)
— it adds a strictly-more-restrictive layer on top.

Four independent stops, evaluated fail-closed (any one denies):

  1. Global halt flag — the one-tap ntfy kill-switch. When set, NOTHING autonomous
     runs; in-flight loops poll :func:`is_halted` / :func:`abort_if_halted` between
     steps and abort.
  2. HITL-FOREVER invariants (HARDCODED, not settings): money, people
     (messaging/contacts), deletion, and physical/home-control actions can NEVER
     self-initiate — no stage, flag, or enabled switch bypasses them.
  3. Circuit breakers (:mod:`src.circuit_breaker`) — per ``tool_type`` and per
     ``goal``. A tripped breaker blocks further autonomous calls on that key.
  4. Global autonomy switch — defaults DISABLED. Nothing self-initiates unless the
     operator explicitly enables it. A tainted context with a high-blast-radius
     action is also forced to human approval.

The halt flag is mirrored to a small JSON file under ``DATA_DIR`` so the
kill-switch route (one request) and the in-flight loop (another) always agree,
and so the halt SURVIVES a restart — during an incident you want it to stay
stopped, not silently re-arm on the next boot.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Optional

from src.constants import DATA_DIR

# Re-export the breaker API so callers/tests use a single ``autonomy_guard``
# namespace for the whole gate.
from src.circuit_breaker import (  # noqa: F401
    BreakerConfig,
    breaker_status,
    configure_breakers,
    goal_key,
    is_tripped,
    record_failure,
    record_success,
    reset,
    reset_all,
    tool_key,
)

logger = logging.getLogger(__name__)

HALT_FILE = os.path.join(DATA_DIR, "autonomy_halt.json")

# ---------------------------------------------------------------------------
# HITL-FOREVER classification (HARDCODED — no setting/flag may bypass these)
# ---------------------------------------------------------------------------
# People: messaging + contacts. Money: payment-shaped tools. Deletion: destructive
# file ops. Physical: home/robot/UI control. Unknown tool types are treated as
# HITL-forever (safest). These sets are additive to — never a replacement for —
# the approval queue's own mutating-tool classification.
_HITL_MESSAGING = {"send_email", "reply_to_email", "bulk_email", "manage_contact"}
_HITL_MONEY: set[str] = set()  # extension point; no money tool ships today
_HITL_DELETION = {"delete_file", "move_file"}
_HITL_PHYSICAL = {"ui_control"}
_METHOD_AWARE = {"api_call", "app_api"}
# Home-control REST shapes reached via api_call (Home Assistant service calls).
_HOME_CONTROL_PATH_MARKERS = ("/api/services/", "/api/events/")


def _parse_api_args(content: Optional[str]) -> dict:
    if not content:
        return {}
    try:
        parsed = json.loads(content)
        return parsed if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def is_hitl_forever(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    """True if this action ALWAYS requires a human — no autonomy stage can bypass it.

    Fail-closed: an unknown/empty tool type, or an api_call whose method/path can't
    be parsed, is treated as HITL-forever.
    """
    if not tool_type:
        return True
    if (
        tool_type in _HITL_MESSAGING
        or tool_type in _HITL_MONEY
        or tool_type in _HITL_DELETION
        or tool_type in _HITL_PHYSICAL
    ):
        return True
    if tool_type in _METHOD_AWARE:
        args = _parse_api_args(content)
        method = str(args.get("method") or "GET").upper()
        if method == "DELETE":  # deletion is HITL-forever
            return True
        path = str(args.get("path") or args.get("url") or "")
        if any(marker in path for marker in _HOME_CONTROL_PATH_MARKERS):
            return True  # physical / home-control
    return False


# ---------------------------------------------------------------------------
# Global halt flag (the kill-switch)
# ---------------------------------------------------------------------------
_lock = threading.RLock()
_halt: Optional[dict] = None


def _write_halt_file(payload: Optional[dict]) -> None:
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if payload is None:
            if os.path.exists(HALT_FILE):
                os.remove(HALT_FILE)
        else:
            tmp = f"{HALT_FILE}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp, HALT_FILE)
    except OSError as exc:  # durability is best-effort; in-memory flag still holds
        logger.warning("autonomy halt file write failed: %s", exc)


def _load_halt_file() -> Optional[dict]:
    try:
        with open(HALT_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def halt(reason: str = "kill-switch", source: str = "ntfy") -> dict:
    """Engage the global kill-switch. Idempotent. Persists across restarts."""
    global _halt
    with _lock:
        _halt = {"reason": str(reason)[:500], "source": str(source)[:64], "at": time.time()}
        _write_halt_file(_halt)
    logger.warning("AUTONOMY HALTED (source=%s): %s", source, reason)
    return dict(_halt)


def resume() -> None:
    """Release the kill-switch, re-enabling autonomous action (subject to the
    autonomy switch + breakers). Explicit operator action only."""
    global _halt
    with _lock:
        _halt = None
        _write_halt_file(None)
    logger.warning("autonomy halt cleared; autonomous action re-enabled")


def is_halted() -> bool:
    """True if the kill-switch is engaged. Consults the persisted file too so a
    halt set in another process/request (or before restart) is always honored."""
    global _halt
    with _lock:
        if _halt is not None:
            return True
        ondisk = _load_halt_file()
        if ondisk is not None:
            _halt = ondisk  # adopt persisted halt
            return True
    return False


def halt_status() -> dict:
    with _lock:
        halted = is_halted()
        return {"halted": halted, "detail": dict(_halt) if (halted and _halt) else None}


# Load any persisted halt on import so a restart mid-incident stays stopped.
_halt = _load_halt_file()


# ---------------------------------------------------------------------------
# Autonomy switch
# ---------------------------------------------------------------------------
def autonomy_enabled() -> bool:
    """Global self-initiation switch. Defaults DISABLED. Fail-closed on any error."""
    try:
        from src.settings import get_setting

        return bool(get_setting("autonomy_enabled", False))
    except Exception:  # settings unreadable → treat autonomy as OFF (safe)
        logger.warning("autonomy_enabled read failed; treating as disabled")
        return False


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------
@dataclass
class Decision:
    allowed: bool
    reason: str
    requires_human: bool = False
    breaker_key: Optional[str] = None


def _tainted_high_blast(session_id: str, tool_type: Optional[str], content: Optional[str]) -> bool:
    """Tainted context + high-blast-radius action → human approval, fail-closed."""
    try:
        from src import context_taint
        from src.pending_actions import is_mutating_tool

        if not context_taint.is_tainted(session_id):
            return False
        return context_taint.is_credentialed_mutator(tool_type, content) or is_mutating_tool(
            tool_type, content
        )
    except Exception:
        return True  # can't evaluate provenance → assume high blast (safe)


# Public alias so admission stages don't reach for the underscore-private name.
tainted_high_blast = _tainted_high_blast


def evaluate(
    tool_type: Optional[str],
    content: Optional[str] = None,
    session_id: Optional[str] = None,
    goal: Optional[str] = None,
) -> Decision:
    """Fail-closed gate for a single self-initiated action.

    Order matters: the hardest stops (halt, HITL-forever, tripped breaker) are
    checked before the autonomy switch so they hold even if someone flips it on.
    """
    if is_halted():
        return Decision(False, "autonomy halted (kill-switch engaged)", requires_human=True)

    if is_hitl_forever(tool_type, content):
        return Decision(
            False, f"HITL-forever action '{tool_type}' always requires human approval",
            requires_human=True,
        )

    tkey = tool_key(tool_type)
    gkey = goal_key(goal)
    for key in (tkey, gkey):
        if key and is_tripped(key):
            return Decision(False, f"circuit breaker tripped: {key}", breaker_key=key)

    if not autonomy_enabled():
        return Decision(False, "autonomy disabled (operator has not enabled self-initiation)",
                        requires_human=True)

    if session_id and _tainted_high_blast(session_id, tool_type, content):
        return Decision(False, "tainted context + high blast radius", requires_human=True)

    return Decision(True, "ok", breaker_key=tkey)


def note_result(tool_type: Optional[str], goal: Optional[str], ok: bool) -> None:
    """Feed a completed autonomous action's outcome to the tool + goal breakers."""
    tkey, gkey = tool_key(tool_type), goal_key(goal)
    if ok:
        record_success(tkey)
        record_success(gkey)
    else:
        record_failure(tkey)
        record_failure(gkey)


class AutonomyHalted(Exception):
    """Raised by :func:`abort_if_halted` to unwind an in-flight autonomous loop."""


def abort_if_halted() -> None:
    """Poll point for in-flight autonomous loops: raise if the kill-switch fired
    mid-run so the loop aborts before its next self-initiated step."""
    if is_halted():
        raise AutonomyHalted("autonomy halted mid-run by kill-switch")
