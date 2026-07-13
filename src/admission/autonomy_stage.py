"""Admission stage for the Phase-4 autonomy stage-machine (MR-19).

This wraps :class:`src.autonomy_stage_machine.StageMachine` as one ordered,
fail-closed admission :class:`~src.admission.types.Gate`. It is the choke point
that decides HOW MUCH self-initiation is allowed, without editing the agent loop.

Semantics:

* **Human-initiated call** (``ctx.autonomous`` is False): ALLOW no-op. Operator
  actions are governed by the other stages (policy-block / taint / confirm), not
  by the autonomy stage-machine.
* **Self-initiated call** (``ctx.autonomous`` is True): consult the machine. The
  action is ALLOWed only if global autonomy is enabled AND the current stage
  permits the action's tier AND it is not hitl-forever AND the session is not
  tainted-high. Every other outcome is a GATE — the self-initiated action is
  held for the operator's approval (human stays in the loop), never silently run.

Ships DISABLED: with autonomy off and at Stage 0 (the safe defaults in
``src/settings.py``), no self-initiated action is ever admitted here.

The machine is built lazily and once, mirroring the module-level pipeline
singleton in the agent loop. All refusals map to GATE (fail-closed): a refused
self-initiated action becomes a human-approval-required one rather than a drop.
"""
from __future__ import annotations

import hashlib
import logging
from typing import TYPE_CHECKING, Optional

from src.admission.types import AdmissionContext, Decision, allow, gate

if TYPE_CHECKING:
    from src.autonomy_stage_machine import StageMachine

logger = logging.getLogger(__name__)

# Human-readable text per stable FSM refusal reason (see autonomy_stage_machine).
_REASON_TEXT = {
    "kill_switch_engaged": "Autonomy kill-switch is engaged; self-initiated action held.",
    "autonomy_disabled": "Autonomy is disabled; this self-initiated action requires approval.",
    "hitl_forever_always_approval": (
        "This action always requires a human (money/people/deletion/physical); "
        "held for approval."
    ),
    "taint_gate_requires_approval": (
        "Session ingested untrusted content; this self-initiated credentialed "
        "action requires approval."
    ),
    "already_executed": "This self-initiated action has already run; held to avoid a replay.",
    "not_self_initiable": "This action is not self-initiable at any stage; held for approval.",
    "stage_too_low": (
        "The current autonomy stage does not permit this self-initiated action; "
        "held for approval."
    ),
}


def _stable_action_id(ctx: AdmissionContext) -> str:
    """Deterministic idempotency id for a self-initiated action.

    Derived from session + tool + content so an identical replay dedups through
    the machine's journal rather than running twice. Uses a truncated SHA-256 of
    the content to keep the id bounded and to avoid leaking full content into ids.
    """
    content = ctx.content or ""
    digest = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:16]
    return f"{ctx.session_id or '-'}:{ctx.tool_type or '-'}:{digest}"


class AutonomyStageStage:
    """Escalate-only guard: gates SELF-INITIATED tool calls via the stage-machine.

    Human-initiated calls (``ctx.autonomous`` False) are a no-op ALLOW. This stage
    only ever ADDS restriction for autonomous calls; it never loosens the other
    stages, so it is registered LAST in the pipeline.
    """

    name = "autonomy_stage"

    def __init__(self, machine: "Optional[StageMachine]" = None) -> None:
        # Built lazily (from the off-by-default production wiring) if not injected,
        # so importing this module never pulls in settings/DB at import time.
        self._machine = machine

    def _get_machine(self) -> "StageMachine":
        if self._machine is None:
            from src.autonomy_defaults import build_default_machine

            self._machine = build_default_machine()
        return self._machine

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        # Human-initiated calls never touch the autonomy machine.
        if not getattr(ctx, "autonomous", False):
            return allow(self.name)

        from src.autonomy_stage_machine import ActionRequest

        request = ActionRequest(
            action_id=_stable_action_id(ctx),
            tool_type=ctx.tool_type or "",
            content=ctx.content,
            session_id=ctx.session_id,
        )
        decision = self._get_machine().admit(request)
        if decision.admitted:
            return allow(self.name)

        reason = _REASON_TEXT.get(
            decision.reason,
            "This self-initiated action is not permitted; held for approval.",
        )
        return gate(reason, self.name)
