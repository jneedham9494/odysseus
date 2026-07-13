"""Escalate-only Llama-Guard admission stage (MR-20, defence-in-depth).

Registered LAST in the pipeline. Because :class:`~src.admission.pipeline.
AdmissionPipeline` returns the FIRST non-ALLOW verdict, this stage only ever runs
on a call that every deterministic stage (policy-block -> taint -> confirm)
already ALLOWed. Its base decision is therefore always ALLOW, so it can only
ESCALATE that to GATE — it can never downgrade a prior GATE/DENY, because those
short-circuit the pipeline before this stage is reached.

It consults the taint->sink classifier in :mod:`src.guard_classifier`, which
composes the hardcoded HITL-FOREVER invariants with an optional served model and
``escalate()``s (never downgrades) the base decision. Off by default
(``guard_classifier_enabled``).

Fail direction: this is the ONE stage that fails OPEN to ALLOW rather than closed
to GATE. Any fault — an unavailable served model, a taint-lookup error, a buggy
guard — leaves the deterministic decision intact. That is safe precisely because
this stage only ever sees already-ALLOWed calls and only ADDS gates: failing to
escalate merely preserves the status quo the deterministic stages chose, and
never crashes the loop. It is defence-in-depth, not the primary gate.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from src.admission.types import AdmissionContext, Decision, allow, gate
from src.guard_classifier import (
    ActionContext,
    Decision as GuardDecision,
    GuardModel,
    GuardResult,
    build_default_guard,
    guard_classifier_enabled,
    guarded_decision,
)

logger = logging.getLogger(__name__)


def _session_tainted(session_id: Optional[str]) -> bool:
    """True if the session ingested untrusted content. Never raises — a lookup
    failure defers to the deterministic decision (treated as untainted here)."""
    try:
        from src.context_taint import is_tainted

        return bool(is_tainted(session_id))
    except Exception:  # noqa: BLE001 - defence-in-depth must not crash the loop
        return False


def _reason_for(result: GuardResult) -> str:
    """Human-readable approval reason built from the classifier's rationale."""
    detail = ", ".join(result.reasons) if result.reasons else "high taint->sink risk"
    return f"Llama-Guard escalated this action for approval: {detail}."


class GuardEscalationStage:
    """Escalate-only guard: turns a would-be ALLOW into GATE on high taint->sink
    risk. Registered LAST so it can only add approvals, never remove them.

    Dependencies are injectable for testing; each defaults to the real
    settings-backed wiring in :mod:`src.guard_classifier`.
    """

    name = "llama_guard"

    def __init__(
        self,
        *,
        enabled_fn: Callable[[], bool] = guard_classifier_enabled,
        guard_factory: Callable[[], Optional[GuardModel]] = build_default_guard,
        taint_fn: Callable[[Optional[str]], bool] = _session_tainted,
    ) -> None:
        self._enabled = enabled_fn
        self._build_guard = guard_factory
        self._tainted = taint_fn

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        # Fail OPEN to ALLOW on any fault: the deterministic stages already ran
        # and this layer only escalates, so it must never crash the loop or
        # invent an approval out of its own uncertainty.
        try:
            if not self._enabled():
                return allow(self.name)
            action = ActionContext(
                tool_type=ctx.tool_type,
                content=ctx.content,
                session_id=ctx.session_id,
                tainted=self._tainted(ctx.session_id),
            )
            result = guarded_decision(action, GuardDecision.ALLOW, self._build_guard())
            if result.decision is not GuardDecision.ALLOW:
                return gate(_reason_for(result), self.name)
            return allow(self.name)
        except Exception as exc:  # noqa: BLE001 - defer to the deterministic gate
            logger.warning(
                "guard stage fault (%s); deterministic decision stands", exc
            )
            return allow(self.name)
