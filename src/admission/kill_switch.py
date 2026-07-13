"""KillSwitchStage — the Phase-4 autonomy safety gate as an admission stage.

This ports the ordered, fail-closed gate that used to live inline in
``stream_agent_loop`` (via ``autonomy_guard.evaluate``) into a single
:class:`~src.admission.types.Gate`. It only ever ADDS restriction on top of the
existing PolicyBlock / Taint / Confirm stages — it never weakens them.

It is a strict NO-OP (``ALLOW``) for human-initiated tool calls
(``ctx.autonomous is False``): the operator's own actions are unaffected. For a
SELF-INITIATED (autonomous) call it runs four independent stops, hardest first,
so an operator-flipped ``autonomy_enabled`` can never bypass the hard ones:

  1. Global halt flag (the one-tap ntfy kill-switch) -> DENY.
  2. HITL-FOREVER invariants — money / people / deletion / physical — always
     require a human -> GATE, even when autonomy is enabled.
  3. A tripped circuit breaker (per tool_type or per goal) -> DENY.
  4. The OFF-by-default global autonomy switch -> GATE.
  5. Tainted context + high-blast-radius action -> GATE.

Fail-closed: if the guard primitives can't be evaluated, the action is DENIED
rather than allowed (mirroring the original "autonomy gate unavailable" block).
The pipeline additionally converts any escaped exception into a GATE, so there is
no path from a fault to ALLOW.
"""
from __future__ import annotations

import logging

from src.admission.types import AdmissionContext, Decision, allow, deny, gate

logger = logging.getLogger(__name__)


class KillSwitchStage:
    """Admission gate for self-initiated actions: kill-switch + breakers + HITL.

    Registered EARLY (right after the hard PolicyBlock stage, before taint) so the
    hardest autonomy stops precede every softer, approval-oriented check.
    """

    name = "autonomy_kill_switch"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        # Human-initiated actions are never touched by the autonomy gate.
        if not getattr(ctx, "autonomous", False):
            return allow(self.name)

        try:
            from src import autonomy_guard as guard

            # 1. Global kill-switch engaged -> hard block.
            if guard.is_halted():
                return deny("autonomy halted (kill-switch engaged)", self.name)

            # 2. HITL-forever invariant: always needs a human, even with autonomy
            #    enabled. Checked before the autonomy switch so it can't be bypassed.
            if guard.is_hitl_forever(ctx.tool_type, ctx.content):
                return gate(
                    f"HITL-forever action '{ctx.tool_type}' always requires human approval",
                    self.name,
                )

            # 3. Tripped circuit breaker (per tool_type or per goal) -> hard block.
            #    Goal is keyed by session_id, matching the original gate call.
            tool_key = guard.tool_key(ctx.tool_type)
            goal_key = guard.goal_key(ctx.session_id)
            for key in (tool_key, goal_key):
                if key and guard.is_tripped(key):
                    return deny(f"circuit breaker tripped: {key}", self.name)

            # 4. Global autonomy switch is OFF by default -> hold for a human.
            if not guard.autonomy_enabled():
                return gate(
                    "autonomy disabled (operator has not enabled self-initiation)",
                    self.name,
                )

            # 5. Tainted context + high-blast-radius action -> hold for a human.
            if ctx.session_id and guard.tainted_high_blast(
                ctx.session_id, ctx.tool_type, ctx.content
            ):
                return gate("tainted context + high blast radius", self.name)

            return allow(self.name)
        except Exception:  # fail-closed: never let a self-initiated action through
            logger.warning(
                "autonomy kill-switch gate check failed for %r; denying (fail-closed)",
                ctx.tool_type,
            )
            return deny("autonomy gate unavailable (fail-closed)", self.name)
