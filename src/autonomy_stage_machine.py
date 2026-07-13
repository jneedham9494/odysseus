"""Autonomy stage-machine (MR-19) — the Phase-4 self-initiation gate.

Phase 4 removes the human from *initiation*: the agent may propose and run
actions nobody explicitly asked for. Per the research this is the highest-risk
capability in the product, so this module is the single, fail-closed choke point
that decides HOW MUCH self-initiation is allowed. It is **safe-by-default and
off-by-default**: it ships with global autonomy DISABLED and at Stage 0.

Stages (monotone; a stage permits everything the stages below it permit):

  0  observe-only   (DEFAULT) — the agent may look, never self-initiate an effect
  1  notify/digest  — may push a notification / digest to the operator
  2  reversible-internal — may make reversible internal changes (e.g. a draft doc)
  3  soft-external drafts — may prepare external drafts (not sent)
  4  ceiling        — a tiny operator-defined allowlist of proven reversible
                      actions (e.g. an email-briefing-to-self actuator)

A proposed self-initiated action is admitted ONLY if ALL hold:
  * the kill-switch is not engaged,
  * global autonomy is enabled,
  * the action's actuator tier is NOT hitl-forever (money/people/deletion/
    physical are ALWAYS human-approved — hardcoded, no stage/flag bypasses it),
  * the session/taint gate passes (tainted -> high-blast-radius = approval),
  * the idempotency journal has not already run this action,
  * the current stage permits the action's required stage.

Stage PROMOTION is gated: it happens ONLY via ``request_promotion`` with an
explicit operator action AND a clean-run precondition (N days, zero violations).
``admit`` NEVER changes the stage, so the machine can never self-promote.

Everything the machine depends on (actuator tiers, kill-switch, taint gate,
idempotency journal, config/state) is an injected interface, so the machine is
unit-testable in isolation. Production wiring lives in
``src/autonomy_defaults.py`` and stays off-by-default.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Optional, Protocol, runtime_checkable

# ── Stages ──────────────────────────────────────────────────────────────────
STAGE_OBSERVE = 0
STAGE_NOTIFY = 1
STAGE_REVERSIBLE_INTERNAL = 2
STAGE_SOFT_EXTERNAL = 3
STAGE_CEILING = 4
MIN_STAGE = STAGE_OBSERVE
MAX_STAGE = STAGE_CEILING

# ── Actuator tiers (Phase-3, MR-16). Mirrored as string constants so this core
# never imports the tiering module directly — it consumes them via TierChecker.
TIER_READ = "read"
TIER_DRAFT = "draft"
TIER_WRITE = "write-gated"
TIER_HITL = "hitl-forever"

# ── Self-initiation "kind": what the action intends to do. Each maps to the
# minimum stage that permits it. A caller may DECLARE a kind (e.g. a read-tier
# tool used to send a notify digest is kind="notify"); the effective required
# stage is the stricter of the declared kind and the actuator-tier baseline.
KIND_OBSERVE = "observe"
KIND_NOTIFY = "notify"
KIND_REVERSIBLE_INTERNAL = "reversible_internal"
KIND_SOFT_EXTERNAL = "soft_external"
KIND_CEILING = "ceiling"

_KIND_STAGE = {
    KIND_OBSERVE: STAGE_OBSERVE,
    KIND_NOTIFY: STAGE_NOTIFY,
    KIND_REVERSIBLE_INTERNAL: STAGE_REVERSIBLE_INTERNAL,
    KIND_SOFT_EXTERNAL: STAGE_SOFT_EXTERNAL,
    KIND_CEILING: STAGE_CEILING,
}

# Baseline required stage per actuator tier. ``None`` means "never self-initiate
# at any stage" (needs a human). write-gated is None here and only becomes
# permissible via the ceiling allowlist (checked in ``_required_stage``).
_TIER_BASELINE_STAGE = {
    TIER_READ: STAGE_OBSERVE,
    TIER_DRAFT: STAGE_REVERSIBLE_INTERNAL,
    TIER_WRITE: None,
    TIER_HITL: None,
}

# ── Refusal reasons (stable strings for logs/audit) ─────────────────────────
R_KILL_SWITCH = "kill_switch_engaged"
R_DISABLED = "autonomy_disabled"
R_HITL_FOREVER = "hitl_forever_always_approval"
R_TAINT = "taint_gate_requires_approval"
R_DUPLICATE = "already_executed"
R_NOT_PERMITTED = "not_self_initiable"
R_STAGE_TOO_LOW = "stage_too_low"


@runtime_checkable
class TierChecker(Protocol):
    """Classifies an actuator into a Phase-3 tier (read/draft/write-gated/
    hitl-forever). Must fail closed — an unknown tool returns write-gated."""

    def tier(self, tool_type: Optional[str], content: Optional[str] = None) -> str: ...


@runtime_checkable
class KillSwitch(Protocol):
    def engaged(self) -> bool: ...


@runtime_checkable
class TaintGate(Protocol):
    """True when a credentialed / high-blast-radius action in this session must
    be human-approved because the session is tainted."""

    def requires_taint_approval(
        self, session_id: Optional[str], tool_type: Optional[str],
        content: Optional[str] = None,
    ) -> bool: ...


@runtime_checkable
class Journal(Protocol):
    """Idempotency / append-only journal (MR-17 interface). ``already_done``
    dedups replays; ``record`` marks an action as run."""

    def already_done(self, action_id: str) -> bool: ...

    def record(self, action_id: str, admitted: bool) -> None: ...


@runtime_checkable
class AutonomyConfig(Protocol):
    """Global autonomy state. ``set_stage`` is the ONLY stage mutator and is
    called exclusively by ``request_promotion`` (never by ``admit``)."""

    def enabled(self) -> bool: ...

    def stage(self) -> int: ...
    def ceiling_allowlist(self) -> FrozenSet[str]: ...
    def set_stage(self, stage: int) -> None: ...


@dataclass(frozen=True)
class ActionRequest:
    """A proposed self-initiated action.

    action_id  — stable id for idempotency (dedup across replays).
    tool_type  — actuator name, tiered by the TierChecker.
    content    — actuator args (JSON string); used for method-aware tiering.
    session_id — session whose taint state gates high-blast actions.
    kind       — declared self-initiation intent (see KIND_*); optional. The
                 effective bar is the stricter of this and the tier baseline.
    """

    action_id: str
    tool_type: str
    content: Optional[str] = None
    session_id: Optional[str] = None
    kind: Optional[str] = None


@dataclass(frozen=True)
class Decision:
    admitted: bool
    reason: str
    tier: Optional[str] = None
    required_stage: Optional[int] = None
    current_stage: Optional[int] = None


@dataclass(frozen=True)
class CleanRun:
    """Evidence for a promotion: consecutive clean days and violation count."""

    clean_days: int
    violations: int


@dataclass(frozen=True)
class PromotionDecision:
    promoted: bool
    reason: str
    new_stage: int


def _required_stage(
    tier: str, kind: Optional[str], allowlisted: bool
) -> Optional[int]:
    """Minimum stage that permits this action, or ``None`` if never self-
    initiable. The stricter (higher) of the tier baseline and the declared
    kind wins; unknown kinds are ignored (fail to the tier baseline)."""
    if tier == TIER_HITL:
        return None  # money/people/deletion/physical — never self-initiated
    baseline = _TIER_BASELINE_STAGE.get(tier)
    if tier == TIER_WRITE:
        # write-gated is only self-initiable if it is an operator-vetted
        # ceiling action; otherwise it needs a human (None).
        baseline = STAGE_CEILING if allowlisted else None
    if baseline is None:
        return None
    declared = _KIND_STAGE.get(kind) if kind is not None else None
    if declared is None:
        return baseline
    return max(baseline, declared)


class StageMachine:
    """The self-initiation admission gate. Construct with injected interfaces;
    call ``admit`` per proposed action and ``request_promotion`` for the
    operator-driven, precondition-gated stage advance."""

    def __init__(
        self,
        *,
        config: AutonomyConfig,
        tier_checker: TierChecker,
        kill_switch: KillSwitch,
        taint_gate: TaintGate,
        journal: Journal,
        required_clean_days: int = 7,
    ) -> None:
        if required_clean_days < 1:
            raise ValueError("required_clean_days must be >= 1")
        self._config = config
        self._tiers = tier_checker
        self._kill = kill_switch
        self._taint = taint_gate
        self._journal = journal
        self._required_clean_days = required_clean_days

    # -- admission ----------------------------------------------------------
    def admit(self, request: ActionRequest) -> Decision:
        """Decide whether a proposed self-initiated action may run. Fail-closed:
        every guard is a refusal, and admission requires ALL guards to pass.
        NEVER mutates the stage."""
        if not request.action_id or not request.tool_type:
            return Decision(False, R_NOT_PERMITTED)

        stage = self._config.stage()

        # 1. Kill-switch beats everything.
        if self._kill.engaged():
            return Decision(False, R_KILL_SWITCH, current_stage=stage)

        # 2. Global autonomy must be explicitly enabled.
        if not self._config.enabled():
            return Decision(False, R_DISABLED, current_stage=stage)

        tier = self._tiers.tier(request.tool_type, request.content)

        # 3. HITL-forever is ALWAYS human-approved — no stage/flag bypass.
        if tier == TIER_HITL:
            return Decision(False, R_HITL_FOREVER, tier=tier, current_stage=stage)

        # 4. Taint gate: tainted session + high-blast action -> approval.
        if self._taint.requires_taint_approval(
            request.session_id, request.tool_type, request.content
        ):
            return Decision(False, R_TAINT, tier=tier, current_stage=stage)

        # 5. Idempotency: never replay an action already journalled.
        if self._journal.already_done(request.action_id):
            return Decision(False, R_DUPLICATE, tier=tier, current_stage=stage)

        # 6. Stage permission.
        allowlisted = request.tool_type in self._config.ceiling_allowlist()
        required = _required_stage(tier, request.kind, allowlisted)
        if required is None:
            return Decision(False, R_NOT_PERMITTED, tier=tier, current_stage=stage)
        if stage < required:
            return Decision(
                False, R_STAGE_TOO_LOW, tier=tier,
                required_stage=required, current_stage=stage,
            )

        # Admitted — journal it so a replay is deduped.
        self._journal.record(request.action_id, True)
        return Decision(
            True, "admitted", tier=tier,
            required_stage=required, current_stage=stage,
        )

    # -- promotion ----------------------------------------------------------
    def request_promotion(
        self, *, operator_action: bool, clean_run: CleanRun
    ) -> PromotionDecision:
        """Advance exactly one stage. Requires an explicit operator action AND
        a clean run (>= N days, zero violations). Without ``operator_action``
        this is a no-op refusal — the machine can NEVER self-promote."""
        current = self._config.stage()
        if not operator_action:
            return PromotionDecision(False, "operator_action_required", current)
        if current >= MAX_STAGE:
            return PromotionDecision(False, "already_at_ceiling", current)
        if clean_run.violations != 0:
            return PromotionDecision(False, "violations_present", current)
        if clean_run.clean_days < self._required_clean_days:
            return PromotionDecision(False, "insufficient_clean_days", current)
        new_stage = current + 1
        self._config.set_stage(new_stage)
        return PromotionDecision(True, "promoted", new_stage)
