"""Tests for the escalate-only Llama-Guard admission stage (MR-20).

These drive :class:`~src.admission.guard_stage.GuardEscalationStage` and its
placement in :func:`~src.admission.pipeline.build_default_pipeline`. The stage's
whole contract is escalate-only + fail-open-to-ALLOW, and its safety rests on
being registered LAST, so the tests assert exactly those properties:

* a high-risk taint->credentialed-sink that earlier stages ALLOWed is escalated
  to GATE;
* an unavailable served model does not crash and leaves the deterministic
  decision standing;
* the stage never un-gates an earlier GATE (guaranteed by first-non-ALLOW-wins
  ordering, with the guard registered last).

Only ``src.admission`` + ``src.guard_classifier`` are exercised — both are
import-light (stdlib only), so no heavy-dep mocking is needed.
"""
from __future__ import annotations

import pytest

from src.admission.guard_stage import GuardEscalationStage
from src.admission.pipeline import AdmissionPipeline, build_default_pipeline
from src.admission.types import AdmissionContext, Verdict, gate
from src.guard_classifier import GuardUnavailable, GuardVerdict, RiskLevel


# --- Helpers -----------------------------------------------------------------

def _ctx(tool_type: str, content: str | None = None, session_id: str = "s") -> AdmissionContext:
    return AdmissionContext(tool_type=tool_type, content=content, session_id=session_id)


def _on() -> bool:
    return True


def _off() -> bool:
    return False


class _DownModel:
    """A served guard that is unavailable — must not fail the stage open-to-gate."""

    def classify(self, ctx):  # noqa: ANN001, ANN201 - test stub
        raise GuardUnavailable("model offline")


class _UnsafeModel:
    """A served guard that flags everything HIGH risk."""

    def classify(self, ctx):  # noqa: ANN001, ANN201 - test stub
        from src.guard_classifier import Decision as GuardDecision

        return GuardVerdict(RiskLevel.HIGH, GuardDecision.APPROVE, "model-unsafe", "model")


class _AlwaysGate:
    name = "always_gate"

    def evaluate(self, ctx: AdmissionContext):
        return gate("earlier stage held this", self.name)


class _ExplodingGuardStage:
    """A stand-in that must never be reached once an earlier stage gates."""

    name = "boom"

    def evaluate(self, ctx: AdmissionContext):
        raise AssertionError("later stage must not run after an earlier non-ALLOW")


# --- Registration / ordering -------------------------------------------------

def test_guard_stage_registered_last_in_default_pipeline():
    """The escalate-only guard must be the final stage so it only sees ALLOWs."""
    names = build_default_pipeline().stage_names
    assert names[-1] == "llama_guard"
    assert names == ["tool_policy_block", "context_taint", "pending_actions", "llama_guard"]


# --- Escalation (the core behaviour) -----------------------------------------

def test_tainted_high_blast_sink_escalated_to_gate():
    """A tainted session taking a high-blast-radius action that earlier stages
    ALLOWed is escalated ALLOW -> GATE by the hardcoded taint->sink invariant."""
    stage = GuardEscalationStage(
        enabled_fn=_on,
        guard_factory=lambda: None,  # rule-based invariants only
        taint_fn=lambda _sid: True,
    )
    decision = stage.evaluate(_ctx("bash", "rm -rf /"))
    assert decision.verdict is Verdict.GATE
    assert decision.stage == "llama_guard"
    assert "taint->sink" in decision.reason


def test_hitl_forever_sink_escalated_to_gate():
    """A HITL-FOREVER 'money' sink is escalated even when untainted."""
    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: None, taint_fn=lambda _sid: False
    )
    body = '{"method": "POST", "url": "https://firefly/api/payment"}'
    decision = stage.evaluate(_ctx("api_call", body))
    assert decision.verdict is Verdict.GATE
    assert "money" in decision.reason


def test_served_model_unsafe_escalates_to_gate():
    """An available served model flagging HIGH risk escalates a would-be ALLOW."""
    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: _UnsafeModel(), taint_fn=lambda _sid: False
    )
    decision = stage.evaluate(_ctx("web_search", "cats"))
    assert decision.verdict is Verdict.GATE
    assert "model-unsafe" in decision.reason


def test_benign_untainted_read_allowed():
    """An untainted read-only action is not over-gated when the guard is on."""
    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: None, taint_fn=lambda _sid: False
    )
    assert stage.evaluate(_ctx("web_search", "cats")).verdict is Verdict.ALLOW


def test_disabled_by_default_is_a_noop():
    """Off by default: even a HITL-forever sink is left ALLOWed by this layer."""
    stage = GuardEscalationStage(
        enabled_fn=_off, guard_factory=lambda: None, taint_fn=lambda _sid: True
    )
    assert stage.evaluate(_ctx("send_email", "hi")).verdict is Verdict.ALLOW


# --- Fail-open-to-ALLOW (defence-in-depth, never crash the loop) -------------

def test_classifier_unavailable_leaves_deterministic_decision_standing():
    """Served model down + no rule invariant fires -> ALLOW (no crash). The
    deterministic stages already decided; this layer defers to them."""
    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: _DownModel(), taint_fn=lambda _sid: False
    )
    assert stage.evaluate(_ctx("web_search", "cats")).verdict is Verdict.ALLOW


def test_taint_lookup_fault_fails_open_to_allow():
    """A fault while resolving taint must not crash the stage — it returns ALLOW."""

    def _boom(_sid):
        raise RuntimeError("taint store unreachable")

    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: None, taint_fn=_boom
    )
    assert stage.evaluate(_ctx("bash", "ls")).verdict is Verdict.ALLOW


def test_guard_factory_fault_fails_open_to_allow():
    """A fault building the served guard must not crash the stage."""

    def _boom():
        raise RuntimeError("cannot build guard")

    stage = GuardEscalationStage(
        enabled_fn=_on, guard_factory=_boom, taint_fn=lambda _sid: False
    )
    assert stage.evaluate(_ctx("web_search", "cats")).verdict is Verdict.ALLOW


# --- Cannot un-gate an earlier decision (ordering guarantee) -----------------

def test_guard_cannot_undo_an_earlier_gate():
    """First-non-ALLOW-wins + last-position means an earlier GATE stands even if
    the guard would have ALLOWed. The guard is never even consulted."""
    pipeline = AdmissionPipeline([_AlwaysGate(), _ExplodingGuardStage()])
    decision = pipeline.evaluate(_ctx("web_search", "cats"))
    assert decision.verdict is Verdict.GATE
    assert decision.stage == "always_gate"


def test_guard_runs_only_after_all_earlier_stages_allow():
    """When earlier stages ALLOW, the last-position guard runs and can escalate."""
    guard = GuardEscalationStage(
        enabled_fn=_on, guard_factory=lambda: None, taint_fn=lambda _sid: True
    )

    class _AllowAll:
        name = "allow_all"

        def evaluate(self, ctx):
            from src.admission.types import allow

            return allow(self.name)

    pipeline = AdmissionPipeline([_AllowAll(), guard])
    decision = pipeline.evaluate(_ctx("bash", "rm -rf /"))
    assert decision.verdict is Verdict.GATE
    assert decision.stage == "llama_guard"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
