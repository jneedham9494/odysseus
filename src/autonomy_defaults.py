"""Production wiring for the autonomy stage-machine (MR-19).

Adapts the injected interfaces in ``src/autonomy_stage_machine.py`` to this
app's real modules, staying **off-by-default**:

  * autonomy is DISABLED and Stage 0 unless the operator explicitly sets the
    ``autonomy_enabled`` / ``autonomy_stage`` settings,
  * the ceiling allowlist is empty by default,
  * tiering defers to the Phase-3 ``actuator_tiers`` module when present and
    **fails closed to write-gated** if it is not (that branch may not be
    merged yet),
  * the taint gate reuses the existing enforced boundary in
    ``src/context_taint.py`` (never weakened here).

The idempotency journal here is a conservative in-process default; the real
MR-17 journal implements the same tiny ``Journal`` interface and is injected in
its place.
"""
from __future__ import annotations

import logging
from typing import FrozenSet, Optional

from src.autonomy_stage_machine import (
    TIER_WRITE,
    StageMachine,
)
from src.settings import get_setting

logger = logging.getLogger(__name__)


class SettingsConfig:
    """AutonomyConfig backed by app settings. Safe defaults: disabled, Stage 0,
    empty ceiling allowlist."""

    def enabled(self) -> bool:
        return bool(get_setting("autonomy_enabled", False))

    def stage(self) -> int:
        try:
            raw = int(get_setting("autonomy_stage", 0))
        except (TypeError, ValueError):
            return 0
        return max(0, min(4, raw))  # clamp into [0, ceiling]

    def ceiling_allowlist(self) -> FrozenSet[str]:
        raw = get_setting("autonomy_ceiling_allowlist", None)
        if isinstance(raw, str):
            items = {t.strip() for t in raw.split(",") if t.strip()}
        elif isinstance(raw, (list, tuple, set)):
            items = {str(t).strip() for t in raw if str(t).strip()}
        else:
            items = set()
        return frozenset(items)

    def set_stage(self, stage: int) -> None:
        # The ONLY stage writer; called by StageMachine.request_promotion after
        # its operator + clean-run checks. Persists atomically via settings.
        from src.settings import load_settings, save_settings

        settings = dict(load_settings())
        settings["autonomy_stage"] = max(0, min(4, int(stage)))
        save_settings(settings)


class SettingsKillSwitch:
    """Engaged when the operator sets ``autonomy_kill_switch`` truthy. Fails
    closed: any read error is treated as ENGAGED (block)."""

    def engaged(self) -> bool:
        try:
            return bool(get_setting("autonomy_kill_switch", False))
        except Exception:  # pragma: no cover - defensive
            logger.warning("kill-switch read failed; treating as ENGAGED")
            return True


class ActuatorTierChecker:
    """Delegates to the Phase-3 ``actuator_tiers`` module. If unavailable
    (branch not merged) or it raises, returns write-gated — fail closed."""

    def tier(self, tool_type: Optional[str], content: Optional[str] = None) -> str:
        try:
            from src.actuator_tiers import actuator_tier

            return actuator_tier(tool_type, content)
        except Exception:
            return TIER_WRITE


class ContextTaintGate:
    """Reuses the existing enforced taint boundary. Fails closed: any error
    means 'requires approval'."""

    def requires_taint_approval(
        self, session_id: Optional[str], tool_type: Optional[str],
        content: Optional[str] = None,
    ) -> bool:
        try:
            from src.context_taint import requires_taint_approval

            return requires_taint_approval(session_id, tool_type, content)
        except Exception:
            return True


class InProcessJournal:
    """Minimal idempotency journal. Records admitted action ids in-process to
    dedup replays. Replace with the MR-17 durable journal (same interface)."""

    def __init__(self) -> None:
        self._done: set[str] = set()

    def already_done(self, action_id: str) -> bool:
        return action_id in self._done

    def record(self, action_id: str, admitted: bool) -> None:
        if admitted:
            self._done.add(action_id)


def build_default_machine(*, required_clean_days: int = 7) -> StageMachine:
    """Wire the production stage-machine. Off-by-default: nothing self-initiates
    unless the operator has enabled autonomy AND raised the stage."""
    return StageMachine(
        config=SettingsConfig(),
        tier_checker=ActuatorTierChecker(),
        kill_switch=SettingsKillSwitch(),
        taint_gate=ContextTaintGate(),
        journal=InProcessJournal(),
        required_clean_days=required_clean_days,
    )
