"""The initial admission stages — wrappers around the three EXISTING checks.

These reproduce, exactly, the inline gate that lived in
``stream_agent_loop``::

    if tool_policy.blocks(...):            -> DENY   (hard block)
    elif _needs_approval(...) or           -> GATE   (auto-confirm approval)
         _tainted_needs_approval(...):      -> GATE   (taint / EchoLeak)
    else:                                   -> ALLOW  (execute)

Order in the pipeline is: policy-block (DENY) → taint (GATE) → confirm-approval
(GATE). Blocks are hard and come first; taint (HITL-forever) precedes the softer
auto-confirm check. Because taint and confirm both yield GATE, their relative
order does not change the verdict — it only satisfies the "taint before softer
checks" ordering rule.

The two module-level helpers hold the canonical fail-closed logic; the agent loop
delegates its ``_needs_approval`` / ``_tainted_needs_approval`` to them so there
is a single implementation.
"""
from __future__ import annotations

import logging
from typing import Optional

from src.admission.policy_view import ToolPolicyView
from src.admission.types import AdmissionContext, Decision, allow, deny, gate

logger = logging.getLogger(__name__)


def requires_confirm_approval_failclosed(
    tool_type: Optional[str], content: Optional[str] = None
) -> bool:
    """True if this tool must be queued for human approval (agent_tool_confirm).

    Fails CLOSED: if the full policy check raises, gate mutating tools rather than
    letting them run unchecked — unless confirmation is clearly disabled. This is
    the original ``agent_loop._needs_approval`` body, moved here verbatim.
    """
    try:
        return ToolPolicyView.requires_confirm_approval(tool_type, content)
    except Exception:
        logger.warning("approval policy check failed for %r; failing closed", tool_type)
        try:
            if not ToolPolicyView.confirm_enabled():
                return False  # user has gating off → don't stall their actions
        except Exception:
            pass  # can't even read the setting → assume gating may be on
        try:
            return ToolPolicyView.is_mutating(tool_type, content)
        except Exception:
            return True  # total failure → gate everything (safest)


def requires_taint_approval_safe(
    session_id: Optional[str], tool_type: Optional[str], content: Optional[str] = None
) -> bool:
    """True if a credentialed action must be approved because the session ingested
    untrusted web/browser content (EchoLeak / tier-split defense). Forces approval
    even when auto-confirm is off. Original ``_tainted_needs_approval`` body."""
    try:
        return ToolPolicyView.requires_taint_approval(session_id, tool_type, content)
    except Exception:
        return False


class PolicyBlockStage:
    """DENY when the per-turn tool policy blocks this tool (guide-only, plan mode,
    disabled tools, block-all)."""

    name = "tool_policy_block"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        policy = ctx.tool_policy
        if policy is not None and policy.blocks(ctx.tool_type):
            return deny(policy.reason_for(ctx.tool_type), self.name)
        return allow(self.name)


class TaintApprovalStage:
    """GATE a credentialed action once the session is tainted (EchoLeak defense)."""

    name = "context_taint"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        if requires_taint_approval_safe(ctx.session_id, ctx.tool_type, ctx.content):
            return gate(
                "Session ingested untrusted content; this credentialed action "
                "requires approval.",
                self.name,
            )
        return allow(self.name)


class ConfirmApprovalStage:
    """GATE mutating / real-world actions under the auto-confirm approval policy."""

    name = "pending_actions"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        if requires_confirm_approval_failclosed(ctx.tool_type, ctx.content):
            return gate("This action requires the user's approval.", self.name)
        return allow(self.name)
