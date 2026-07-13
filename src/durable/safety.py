"""Phase-4 initiation safety for the durable executor (MR-17).

Removing the human from *initiation* is the highest-risk change in the system, so
this gate is SAFE-BY-DEFAULT and OFF-BY-DEFAULT. It answers one question before
any side effect runs: *may this action fire without a human, right now?*

Hardcoded invariants (NOT settings — no stage/flag/setting can bypass them):
  - HITL-FOREVER categories — money, people (messaging/contacts), deletion, and
    physical/home-control — ALWAYS require human approval.
  - A tainted session performing a high-blast-radius action ALWAYS requires
    human approval (extends the EchoLeak defense in ``src/context_taint.py``).
  - Any classification error fails CLOSED (requires approval).

Autonomy (self-initiated actions with no human trigger) additionally requires the
global autonomy switch to be explicitly enabled; it defaults DISABLED.

The environment reads (autonomy setting, taint check) are injected so the gate is
pure and unit-testable in isolation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


# ── Action categories ───────────────────────────────────────────────────────
CATEGORY_MONEY = "money"
CATEGORY_PEOPLE = "people"          # messaging / contacts — reaching real humans
CATEGORY_DELETION = "deletion"
CATEGORY_PHYSICAL = "physical"      # home-control / physical-world actuation
CATEGORY_GENERAL = "general"

# Hardcoded, not configurable. Membership here forces human approval forever.
HITL_FOREVER: frozenset = frozenset({
    CATEGORY_MONEY, CATEGORY_PEOPLE, CATEGORY_DELETION, CATEGORY_PHYSICAL,
})

# ── Blast radius ────────────────────────────────────────────────────────────
BLAST_LOW = "low"
BLAST_MEDIUM = "medium"
BLAST_HIGH = "high"
_BLAST_RANK = {BLAST_LOW: 0, BLAST_MEDIUM: 1, BLAST_HIGH: 2}

# Global autonomy switch. Absent/unset -> disabled (fail closed).
AUTONOMY_SETTING_KEY = "autonomy_enabled"

# Coarse tool_type -> category map for callers that pass a tool name instead of a
# category. Unmapped tools are classified GENERAL but callers SHOULD pass an
# explicit category for anything world-changing; the gate itself never downgrades.
_TOOL_CATEGORY = {
    "send_email": CATEGORY_PEOPLE, "reply_to_email": CATEGORY_PEOPLE,
    "bulk_email": CATEGORY_PEOPLE, "manage_contact": CATEGORY_PEOPLE,
    "delete_file": CATEGORY_DELETION, "move_file": CATEGORY_DELETION,
    "ui_control": CATEGORY_PHYSICAL,
}


def classify_category(tool_type: Optional[str]) -> str:
    """Best-effort category from a tool name. Never used to *lower* an explicit
    category — only to supply one when the caller gave none."""
    if not tool_type:
        return CATEGORY_GENERAL
    if tool_type in _TOOL_CATEGORY:
        return _TOOL_CATEGORY[tool_type]
    if tool_type.startswith(("home_", "ha_", "hass_")):
        return CATEGORY_PHYSICAL
    return CATEGORY_GENERAL


def blast_at_least_high(blast_radius: Optional[str]) -> bool:
    return _BLAST_RANK.get(blast_radius or BLAST_LOW, _BLAST_RANK[BLAST_HIGH]) >= _BLAST_RANK[BLAST_HIGH]


@dataclass(frozen=True)
class GateDecision:
    """Outcome of the safety gate. ``requires_human`` True means DO NOT auto-run;
    route to the human approval queue instead."""

    requires_human: bool
    reason: str


def _default_autonomy_enabled() -> bool:
    """Read the global autonomy switch, defaulting DISABLED and failing closed."""
    try:
        from src.settings import get_setting
        return bool(get_setting(AUTONOMY_SETTING_KEY, False))
    except Exception:
        return False  # can't read setting -> assume autonomy OFF


def _default_is_tainted(session_id: Optional[str]) -> bool:
    try:
        from src.context_taint import is_tainted
        return bool(is_tainted(session_id))
    except Exception:
        return True  # can't evaluate taint -> assume tainted (fail closed)


class SafetyGate:
    """Decides whether an action may fire without a human. Fail-closed by design.

    Dependencies are injected so the gate is pure in tests: pass an
    ``autonomy_enabled`` predicate and an ``is_tainted`` predicate.
    """

    def __init__(
        self,
        autonomy_enabled: Callable[[], bool] = _default_autonomy_enabled,
        is_tainted: Callable[[Optional[str]], bool] = _default_is_tainted,
    ) -> None:
        self._autonomy_enabled = autonomy_enabled
        self._is_tainted = is_tainted

    def evaluate(
        self,
        *,
        category: str,
        blast_radius: str,
        session_id: Optional[str],
        self_initiated: bool,
    ) -> GateDecision:
        """Return a GateDecision. Order matters: hardcoded invariants first, then
        autonomy, then taint. ANY exception -> require human (fail closed)."""
        try:
            # 1. HITL-FOREVER: money / people / deletion / physical. No bypass.
            if category in HITL_FOREVER:
                return GateDecision(True, f"category '{category}' always requires human approval")

            # 2. tainted + high blast radius -> human, always (EchoLeak extension).
            if blast_at_least_high(blast_radius) and self._is_tainted(session_id):
                return GateDecision(True, "high-blast-radius action in a tainted session")

            # 3. Self-initiated actions need the global autonomy switch ON.
            if self_initiated and not self._autonomy_enabled():
                return GateDecision(True, "autonomy disabled: self-initiated action needs approval")

            return GateDecision(False, "permitted")
        except Exception as exc:  # noqa: BLE001 - fail closed on any error
            return GateDecision(True, f"gate evaluation error (fail-closed): {exc}")
