"""The ordered, fail-closed tool-admission pipeline.

Stages run in a FIXED order. The first stage to return a non-ALLOW verdict wins;
if every stage allows, the call is ALLOWed. The pipeline is FAIL-CLOSED: a stage
that raises, or returns anything other than a :class:`Decision`, yields GATE (hold
for approval) — it can never fall through to ALLOW.

Future work (autonomy, toolcall-validate, llama-guard) ADDS a stage via
:meth:`AdmissionPipeline.register_stage` instead of editing the agent loop.
"""
from __future__ import annotations

import logging
from typing import List, Optional, Sequence

from src.admission.kill_switch import KillSwitchStage
from src.admission.stages import (
    ConfirmApprovalStage,
    PolicyBlockStage,
    TaintApprovalStage,
)
from src.admission.toolcall_validation import ToolCallValidationStage
from src.admission.types import AdmissionContext, Decision, Gate, Verdict, allow, gate

logger = logging.getLogger(__name__)


class AdmissionPipeline:
    """Runs admission stages in order and returns the first non-ALLOW decision."""

    def __init__(self, stages: Sequence[Gate]):
        self._stages: List[Gate] = list(stages)

    @property
    def stage_names(self) -> List[str]:
        return [self._stage_name(s) for s in self._stages]

    @staticmethod
    def _stage_name(stage: Gate) -> str:
        return getattr(stage, "name", None) or stage.__class__.__name__

    def register_stage(self, stage: Gate, *, position: Optional[int] = None) -> None:
        """Add a stage. Appends by default; ``position`` inserts at an index.

        This is the extension seam: new gates are registered here rather than
        edited into the agent loop. A registered stage participates in ordering
        and fail-closed handling exactly like the built-ins.
        """
        if position is None:
            self._stages.append(stage)
        else:
            self._stages.insert(position, stage)

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        """First non-ALLOW verdict wins; fail closed to GATE on any stage fault."""
        for stage in self._stages:
            name = self._stage_name(stage)
            try:
                decision = stage.evaluate(ctx)
            except Exception as exc:  # fail closed: never let a fault ALLOW
                logger.warning("admission stage %s raised; failing closed: %s", name, exc)
                return gate(f"Admission stage {name} failed; holding for approval.", name)
            if not isinstance(decision, Decision):
                logger.warning(
                    "admission stage %s returned %r (not a Decision); failing closed",
                    name, type(decision).__name__,
                )
                return gate(f"Admission stage {name} returned an unknown verdict.", name)
            if decision.verdict is Verdict.ALLOW:
                continue
            return decision
        return allow()


def build_default_pipeline() -> AdmissionPipeline:
    """The default pipeline: validate → hard block → kill-switch → taint → confirm.

    Ordering rationale: toolcall-validation runs FIRST so a malformed or unknown
    call is DENIED before any policy/autonomy/taint/approval stage considers it —
    a call that cannot be dispatched should never be gated for a human either.
    PolicyBlock (hard DENY) is next. The autonomy kill-switch follows — a no-op
    for human-initiated calls, but for self-initiated ones it applies the hardest
    autonomy stops (halt/breaker DENY, HITL-forever/autonomy-off GATE) before the
    softer taint (EchoLeak) GATE and auto-confirm approval GATE.
    """
    return AdmissionPipeline(
        [
            ToolCallValidationStage(),
            PolicyBlockStage(),
            KillSwitchStage(),
            TaintApprovalStage(),
            ConfirmApprovalStage(),
        ]
    )
