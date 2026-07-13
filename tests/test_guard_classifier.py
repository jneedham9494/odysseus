"""Tests for the MR-20 Llama-Guard taint->sink defence-in-depth classifier.

Covers the three contract guarantees from the spec:
  1. A high-risk tainted -> credentialed-sink action is flagged (escalated).
  2. The classifier NEVER downgrades a deterministic-gate decision (escalate only).
  3. A classifier-unavailable model falls back to the deterministic gate
     (fail-closed, not fail-open).
Plus the HITL-FOREVER invariants and the autonomy safety net.
"""
from __future__ import annotations

import pytest

from src.guard_classifier import (
    ActionContext,
    Decision,
    GuardResult,
    GuardUnavailable,
    GuardVerdict,
    LiteLLMGuard,
    RiskLevel,
    RuleBasedGuard,
    escalate,
    guarded_decision,
    hitl_forever_category,
    is_high_blast_radius,
)


# --- Stub guard models (injected; no network) --------------------------------

class _SafeGuard:
    """A model that always says the action is safe (low risk)."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        return GuardVerdict(RiskLevel.LOW, Decision.ALLOW, "", "model")


class _UnsafeGuard:
    """A model that always says the action is unsafe (high risk)."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        return GuardVerdict(RiskLevel.HIGH, Decision.APPROVE, "model-unsafe", "model")


class _DownGuard:
    """A misbehaving model that tries to DOWNGRADE to ALLOW (must be ignored)."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        return GuardVerdict(RiskLevel.LOW, Decision.ALLOW, "", "model")


class _BrokenGuard:
    """A model that is unavailable (raises)."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        raise GuardUnavailable("served model unreachable")


class _CrashGuard:
    """A buggy model that raises an unexpected error (not GuardUnavailable)."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        raise RuntimeError("boom")


# --- escalate() ladder -------------------------------------------------------

def test_escalate_returns_more_severe_decision():
    assert escalate(Decision.ALLOW, Decision.APPROVE) is Decision.APPROVE
    assert escalate(Decision.APPROVE, Decision.ALLOW) is Decision.APPROVE
    assert escalate(Decision.BLOCK, Decision.APPROVE) is Decision.BLOCK
    assert escalate(Decision.ALLOW, Decision.ALLOW) is Decision.ALLOW


# --- Guarantee 1: high-risk tainted -> credentialed sink is flagged ----------

def test_tainted_credentialed_sink_is_flagged_by_rule_net():
    # send_email in a tainted session, gate said ALLOW -> guard must escalate.
    ctx = ActionContext(tool_type="send_email", tainted=True, session_id="s1")
    result = guarded_decision(ctx, Decision.ALLOW, guard=None)
    assert result.decision is Decision.APPROVE
    assert result.escalated is True


def test_tainted_write_api_call_is_flagged():
    ctx = ActionContext(
        tool_type="api_call",
        content='{"method": "POST", "url": "https://api.example.com/x"}',
        tainted=True,
    )
    result = guarded_decision(ctx, Decision.ALLOW, guard=None)
    assert result.decision is Decision.APPROVE


def test_untainted_read_api_call_is_not_flagged():
    ctx = ActionContext(
        tool_type="api_call",
        content='{"method": "GET", "url": "https://api.example.com/x"}',
        tainted=True,  # tainted, but a GET is not a high-blast sink
    )
    result = guarded_decision(ctx, Decision.ALLOW, guard=None)
    assert result.decision is Decision.ALLOW


def test_model_guard_flags_when_deterministic_gate_missed():
    # Gate allowed and rule net sees nothing, but the served model says unsafe.
    ctx = ActionContext(tool_type="web_fetch", tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=_UnsafeGuard())
    assert result.decision is Decision.APPROVE
    assert any("model" in r for r in result.reasons)


# --- Guarantee 2: classifier NEVER downgrades a gate decision ----------------

@pytest.mark.parametrize("base", [Decision.APPROVE, Decision.BLOCK])
def test_safe_model_never_downgrades_gate_decision(base):
    ctx = ActionContext(tool_type="write_file", tainted=False)
    result = guarded_decision(ctx, base, guard=_SafeGuard())
    assert result.decision is base
    assert result.escalated is False


def test_misbehaving_model_cannot_downgrade_block():
    ctx = ActionContext(tool_type="bash", tainted=False)
    result = guarded_decision(ctx, Decision.BLOCK, guard=_DownGuard())
    assert result.decision is Decision.BLOCK


def test_rule_net_cannot_downgrade_block_for_benign_action():
    # A benign, untainted read while the gate already blocked -> stays blocked.
    ctx = ActionContext(tool_type="web_search", tainted=False)
    result = guarded_decision(ctx, Decision.BLOCK, guard=None)
    assert result.decision is Decision.BLOCK


def test_guarded_decision_never_returns_below_base_property():
    rank = {Decision.ALLOW: 0, Decision.APPROVE: 1, Decision.BLOCK: 2}
    for base in Decision:
        for guard in (None, _SafeGuard(), _UnsafeGuard(), _BrokenGuard()):
            ctx = ActionContext(tool_type="send_email", tainted=True)
            result = guarded_decision(ctx, base, guard=guard)
            assert rank[result.decision] >= rank[base]


# --- Guarantee 3: classifier-unavailable -> deterministic gate (fail-closed) -

def test_unavailable_model_falls_back_to_gate_decision():
    # Model unavailable, benign untainted action: gate's ALLOW stands (no crash).
    ctx = ActionContext(tool_type="web_search", tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=_BrokenGuard())
    assert result.decision is Decision.ALLOW
    assert any("guard-unavailable" in r for r in result.reasons)


def test_unavailable_model_does_not_downgrade_gate_approval():
    ctx = ActionContext(tool_type="web_search", tainted=False)
    result = guarded_decision(ctx, Decision.APPROVE, guard=_BrokenGuard())
    assert result.decision is Decision.APPROVE


def test_unavailable_model_still_honours_rule_net_invariants():
    # Fail-closed: even with the model down, a tainted sink is still escalated.
    ctx = ActionContext(tool_type="send_email", tainted=True)
    result = guarded_decision(ctx, Decision.ALLOW, guard=_BrokenGuard())
    assert result.decision is Decision.APPROVE


def test_buggy_model_error_falls_back_to_gate_not_fail_open():
    ctx = ActionContext(tool_type="write_file", tainted=False)
    result = guarded_decision(ctx, Decision.APPROVE, guard=_CrashGuard())
    assert result.decision is Decision.APPROVE
    assert any("guard-error" in r for r in result.reasons)


# --- HITL-FOREVER invariants (hardcoded, un-bypassable) ----------------------

@pytest.mark.parametrize(
    "tool_type,expected",
    [
        ("send_email", "people"),
        ("manage_contact", "people"),
        ("send_sms", "people"),
        ("delete_file", "deletion"),
        ("firefly_transfer", "money"),
        ("pay_invoice", "money"),
        ("ha_light_control", "home_control"),
        ("ui_control", "home_control"),
        ("web_search", None),
        ("read_file", None),
    ],
)
def test_hitl_forever_category_classification(tool_type, expected):
    assert hitl_forever_category(tool_type, None) == expected


def test_delete_api_call_is_hitl_forever_deletion():
    assert hitl_forever_category(
        "api_call", '{"method": "DELETE", "url": "https://x/y"}'
    ) == "deletion"


def test_hitl_forever_always_approves_even_untainted_and_model_safe():
    # Money action, untainted, model says safe -> still forced to approval.
    ctx = ActionContext(tool_type="pay_invoice", tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=_SafeGuard())
    assert result.decision is Decision.APPROVE
    assert any("invariant:money" in r for r in result.reasons)


# --- Autonomy safety net -----------------------------------------------------

def test_autonomous_high_blast_action_is_escalated():
    ctx = ActionContext(tool_type="bash", autonomous=True, tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=None)
    assert result.decision is Decision.APPROVE


def test_non_autonomous_benign_action_runs_free():
    ctx = ActionContext(tool_type="web_search", autonomous=False, tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=None)
    assert result.decision is Decision.ALLOW


# --- Sink taxonomy helpers ---------------------------------------------------

def test_is_high_blast_radius_true_for_sinks():
    assert is_high_blast_radius("send_email") is True
    assert is_high_blast_radius("bash") is True
    assert is_high_blast_radius("browser_click") is True
    assert is_high_blast_radius("api_call", '{"method": "PUT"}') is True


def test_is_high_blast_radius_false_for_reads():
    assert is_high_blast_radius("web_search") is False
    assert is_high_blast_radius("api_call", '{"method": "GET"}') is False
    assert is_high_blast_radius(None) is False


# --- LiteLLMGuard parsing (Llama-Guard style safe/unsafe output) -------------

def test_litellm_guard_parses_unsafe():
    guard = LiteLLMGuard(lambda _p: "unsafe\nS2: exfiltration")
    verdict = guard.classify(ActionContext(tool_type="send_email", tainted=True))
    assert verdict.risk is RiskLevel.HIGH
    assert verdict.decision is Decision.APPROVE


def test_litellm_guard_parses_safe():
    guard = LiteLLMGuard(lambda _p: "safe")
    verdict = guard.classify(ActionContext(tool_type="web_search"))
    assert verdict.risk is RiskLevel.LOW


def test_litellm_guard_empty_response_is_unavailable():
    guard = LiteLLMGuard(lambda _p: "")
    with pytest.raises(GuardUnavailable):
        guard.classify(ActionContext(tool_type="web_search"))


def test_litellm_guard_completion_error_is_unavailable():
    def _boom(_p: str) -> str:
        raise ConnectionError("model down")

    guard = LiteLLMGuard(_boom)
    with pytest.raises(GuardUnavailable):
        guard.classify(ActionContext(tool_type="web_search"))


def test_litellm_guard_end_to_end_escalates_through_orchestrator():
    guard = LiteLLMGuard(lambda _p: "unsafe\nS5")
    ctx = ActionContext(tool_type="web_fetch", tainted=False)
    result = guarded_decision(ctx, Decision.ALLOW, guard=guard)
    assert result.decision is Decision.APPROVE


# --- RuleBasedGuard direct ---------------------------------------------------

def test_rule_based_guard_low_for_benign():
    verdict = RuleBasedGuard().classify(ActionContext(tool_type="web_search"))
    assert verdict.risk is RiskLevel.LOW


def test_guard_result_is_frozen_dataclass():
    result = GuardResult(Decision.APPROVE, Decision.ALLOW, ("x",))
    with pytest.raises(Exception):
        result.decision = Decision.BLOCK  # type: ignore[misc]
