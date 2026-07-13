"""Characterization + pipeline tests for the tool-admission gate.

Behavior-preserving proof: the new ordered pipeline must yield the SAME decision
(allow / gate / block) as the ORIGINAL inline if/elif/else that lived in
``stream_agent_loop``. ``_old_inline_decision`` below is a faithful, independent
re-implementation of that pre-refactor logic, written directly against the
underlying modules (pending_actions / context_taint / tool_policy) — NOT against
the new package — so equality with the pipeline demonstrates preservation.
"""
from __future__ import annotations

from typing import Optional

import src.context_taint as context_taint
import src.pending_actions as pending_actions
from src.admission import (
    AdmissionContext,
    AdmissionPipeline,
    Verdict,
    build_default_pipeline,
)
from src.admission.types import Decision, allow, deny, gate
from src.tool_policy import ToolPolicy


# --- reference: the ORIGINAL inline gate, re-implemented independently ---

def _old_inline_decision(
    tool_policy: Optional[ToolPolicy],
    session_id: Optional[str],
    tool_type: Optional[str],
    content: Optional[str],
) -> str:
    """Verbatim pre-refactor happy-path logic → 'block' | 'gate' | 'allow'."""
    if tool_policy and tool_policy.blocks(tool_type):
        return "block"
    needs = bool(pending_actions.requires_approval(tool_type, content))
    taint = bool(context_taint.requires_taint_approval(session_id, tool_type, content))
    if needs or taint:
        return "gate"
    return "allow"


_VERDICT_TO_STR = {
    Verdict.DENY: "block",
    Verdict.GATE: "gate",
    Verdict.ALLOW: "allow",
}


def _pipeline_decision(pipeline, tool_policy, session_id, tool_type, content) -> str:
    decision = pipeline.evaluate(AdmissionContext(
        tool_type=tool_type, content=content, session_id=session_id,
        tool_policy=tool_policy,
    ))
    return _VERDICT_TO_STR[decision.verdict]


# --- shared fixtures/helpers ---

def _confirm_on(monkeypatch, on: bool) -> None:
    """Control the auto-confirm gate without touching settings files/DB."""
    monkeypatch.setattr(pending_actions, "confirm_enabled", lambda: on)
    monkeypatch.setattr(pending_actions, "get_setting", lambda *a, **k: None)


# ---------------------------------------------------------------------------
# Characterization: pipeline == old inline logic, across the four scenarios.
# ---------------------------------------------------------------------------

def test_plain_read_allows_and_matches_old(monkeypatch):
    _confirm_on(monkeypatch, True)  # even with gating ON, a read is not gated
    pipeline = build_default_pipeline()
    old = _old_inline_decision(None, "s1", "web_search", "cats")
    new = _pipeline_decision(pipeline, None, "s1", "web_search", "cats")
    assert old == "allow"
    assert new == old


def test_default_gated_write_gates_and_matches_old(monkeypatch):
    _confirm_on(monkeypatch, True)
    pipeline = build_default_pipeline()
    # write_file ∈ DEFAULT_GATED_TOOLS → queued for approval.
    old = _old_inline_decision(None, "s1", "write_file", "/tmp/x\nhi")
    new = _pipeline_decision(pipeline, None, "s1", "write_file", "/tmp/x\nhi")
    assert old == "gate"
    assert new == old


def test_tainted_credentialed_mutator_gates_and_matches_old(monkeypatch):
    _confirm_on(monkeypatch, False)  # auto-confirm OFF: taint gate must still fire
    context_taint.mark_tainted("tainted-sess")
    try:
        pipeline = build_default_pipeline()
        # send_email ∈ _CREDENTIALED_MUTATORS; session is tainted → EchoLeak gate.
        old = _old_inline_decision(None, "tainted-sess", "send_email", "hi")
        new = _pipeline_decision(pipeline, None, "tainted-sess", "send_email", "hi")
        assert old == "gate"
        assert new == old
        # Sanity: same tool in a CLEAN session with confirm off is allowed.
        assert _pipeline_decision(pipeline, None, "clean", "send_email", "hi") == "allow"
    finally:
        context_taint.clear("tainted-sess")


def test_tool_policy_blocked_denies_and_matches_old(monkeypatch):
    _confirm_on(monkeypatch, True)
    policy = ToolPolicy(disabled_tools=frozenset({"bash"}))
    pipeline = build_default_pipeline()
    old = _old_inline_decision(policy, "s1", "bash", "rm -rf /")
    new = _pipeline_decision(pipeline, policy, "s1", "bash", "rm -rf /")
    assert old == "block"
    assert new == old


def test_block_precedes_gate(monkeypatch):
    """A tool that is BOTH policy-blocked AND approval-gated must resolve to block
    (DENY wins), exactly as the old if/elif ordering did."""
    _confirm_on(monkeypatch, True)
    policy = ToolPolicy(disabled_tools=frozenset({"write_file"}))
    pipeline = build_default_pipeline()
    old = _old_inline_decision(policy, "s1", "write_file", "/tmp/x")
    new = _pipeline_decision(pipeline, policy, "s1", "write_file", "/tmp/x")
    assert old == "block"
    assert new == old


# ---------------------------------------------------------------------------
# Pipeline-level: fail-closed, ordering, register_stage.
# ---------------------------------------------------------------------------

class _RaisingStage:
    name = "boom"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        raise RuntimeError("stage exploded")


class _ForceGateStage:
    name = "force_gate"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        return gate("forced by extension stage", self.name)


class _ForceDenyStage:
    name = "force_deny"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        return deny("forced deny", self.name)


class _BadReturnStage:
    name = "bad_return"

    def evaluate(self, ctx: AdmissionContext):
        return "not-a-decision"  # unknown type → fail closed


def _ctx() -> AdmissionContext:
    return AdmissionContext(tool_type="read_file", content="x", session_id="s")


def test_fail_closed_when_stage_raises():
    pipeline = AdmissionPipeline([_RaisingStage()])
    decision = pipeline.evaluate(_ctx())
    assert decision.verdict is Verdict.GATE  # never ALLOW on a fault
    assert decision.stage == "boom"


def test_fail_closed_on_unknown_return_type():
    pipeline = AdmissionPipeline([_BadReturnStage()])
    decision = pipeline.evaluate(_ctx())
    assert decision.verdict is Verdict.GATE


def test_raising_stage_does_not_leak_to_allow_via_later_stage():
    # Even if a later stage would ALLOW, the earlier fault short-circuits to GATE.
    pipeline = AdmissionPipeline([_RaisingStage(), _AlwaysAllowStage()])
    assert pipeline.evaluate(_ctx()).verdict is Verdict.GATE


class _AlwaysAllowStage:
    name = "allow_all"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        return allow(self.name)


def test_order_first_nonallow_wins():
    # deny registered before gate → deny wins; reversed → gate wins.
    deny_first = AdmissionPipeline([_ForceDenyStage(), _ForceGateStage()])
    gate_first = AdmissionPipeline([_ForceGateStage(), _ForceDenyStage()])
    assert deny_first.evaluate(_ctx()).verdict is Verdict.DENY
    assert gate_first.evaluate(_ctx()).verdict is Verdict.GATE


def test_all_allow_yields_allow():
    pipeline = AdmissionPipeline([_AlwaysAllowStage(), _AlwaysAllowStage()])
    assert pipeline.evaluate(_ctx()).verdict is Verdict.ALLOW


def test_register_stage_can_force_gate(monkeypatch):
    _confirm_on(monkeypatch, False)
    pipeline = build_default_pipeline()
    # Baseline: a plain read is allowed by the default pipeline.
    assert _pipeline_decision(pipeline, None, "s", "read_file", "x") == "allow"
    # A future MR registers a gate → the same call is now held for approval.
    pipeline.register_stage(_ForceGateStage())
    assert _pipeline_decision(pipeline, None, "s", "read_file", "x") == "gate"


def test_register_stage_at_position_respects_order():
    pipeline = AdmissionPipeline([_AlwaysAllowStage()])
    pipeline.register_stage(_ForceDenyStage(), position=0)
    pipeline.register_stage(_ForceGateStage(), position=0)
    # Gate is now first → gate wins over the later deny.
    assert pipeline.evaluate(_ctx()).verdict is Verdict.GATE
    assert pipeline.stage_names[0] == "force_gate"


def test_default_pipeline_stage_order():
    names = build_default_pipeline().stage_names
    # Validation first (a malformed/unknown call is denied before any other stage
    # sees it), then hard block, then the autonomy kill-switch (no-op for human
    # calls), then taint (HITL) before the softer auto-confirm check. The autonomy
    # stage-machine is registered LAST as an escalate-only, self-initiated-only guard.
    assert names == [
        "toolcall_validation",
        "tool_policy_block",
        "autonomy_kill_switch",
        "context_taint",
        "pending_actions",
        "autonomy_stage",
    ]
