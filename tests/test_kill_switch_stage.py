"""Tests for the autonomy KillSwitchStage admission gate.

Covers the ported Phase-4 gate behavior, now expressed as an admission stage:

  * an autonomous call is BLOCKED (DENY) when the kill-switch is engaged,
  * an autonomous call is BLOCKED (DENY) when its circuit breaker is tripped,
  * an autonomous call is GATED when the global autonomy switch is off,
  * HITL-forever actions are GATED even with autonomy fully enabled,
  * a human-initiated call is unaffected (ALLOW),
  * the stage is fail-closed: if the guard can't be evaluated it DENIES.

The pipeline-level fail-closed behavior (a raising stage -> GATE) is also
exercised end-to-end through ``build_default_pipeline``.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.admission import (  # noqa: E402
    AdmissionContext,
    KillSwitchStage,
    Verdict,
    build_default_pipeline,
)
from src.admission.kill_switch import KillSwitchStage as DirectStage  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_autonomy_state(tmp_path, monkeypatch):
    """Isolate halt-file + breaker + settings state for every test."""
    import src.circuit_breaker as cb

    # Redirect the persisted halt file into a temp dir and reload the guard so it
    # binds HALT_FILE to the temp location with no pre-existing halt.
    monkeypatch.setattr("src.constants.DATA_DIR", str(tmp_path), raising=False)
    import src.autonomy_guard as guard

    guard = importlib.reload(guard)
    guard.resume()  # ensure no in-memory/on-disk halt leaks in
    cb.reset_all()

    # Default settings: autonomy OFF unless a test enables it.
    settings_state = {"autonomy_enabled": False}

    def fake_get_setting(key, default=None):
        return settings_state.get(key, default)

    monkeypatch.setattr("src.settings.get_setting", fake_get_setting)
    yield guard, cb, settings_state
    guard.resume()
    cb.reset_all()


def _ctx(tool_type="bash", *, autonomous=True, session_id="s1", content="ls"):
    return AdmissionContext(
        tool_type=tool_type,
        content=content,
        session_id=session_id,
        autonomous=autonomous,
    )


# --------------------------------------------------------------------------- #
# Kill-switch (global halt)
# --------------------------------------------------------------------------- #
def test_autonomous_call_denied_when_halt_set(_clean_autonomy_state):
    guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True  # even with autonomy on, halt wins
    guard.halt(reason="test", source="unit")

    decision = KillSwitchStage().evaluate(_ctx("bash"))

    assert decision.verdict is Verdict.DENY
    assert "halt" in decision.reason.lower()


# --------------------------------------------------------------------------- #
# Circuit breaker
# --------------------------------------------------------------------------- #
def test_autonomous_call_denied_when_breaker_tripped(_clean_autonomy_state):
    guard, cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True
    key = guard.tool_key("bash")
    for _ in range(cb.DEFAULT_FAILURE_THRESHOLD):
        cb.record_failure(key)
    assert cb.is_tripped(key)

    decision = KillSwitchStage().evaluate(_ctx("bash"))

    assert decision.verdict is Verdict.DENY
    assert "circuit breaker" in decision.reason.lower()


# --------------------------------------------------------------------------- #
# Autonomy switch off
# --------------------------------------------------------------------------- #
def test_autonomous_call_gated_when_autonomy_off(_clean_autonomy_state):
    _guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = False

    decision = KillSwitchStage().evaluate(_ctx("bash"))

    assert decision.verdict is Verdict.GATE
    assert "autonomy disabled" in decision.reason.lower()


# --------------------------------------------------------------------------- #
# HITL-forever always gated, even with autonomy enabled
# --------------------------------------------------------------------------- #
def test_hitl_forever_gated_even_with_autonomy_enabled(_clean_autonomy_state):
    _guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True

    decision = KillSwitchStage().evaluate(_ctx("send_email", content="{}"))

    assert decision.verdict is Verdict.GATE
    assert "hitl-forever" in decision.reason.lower()


def test_unknown_tool_treated_as_hitl_forever(_clean_autonomy_state):
    _guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True

    decision = KillSwitchStage().evaluate(_ctx(None, content=None))

    assert decision.verdict is Verdict.GATE


# --------------------------------------------------------------------------- #
# Happy path: autonomy enabled, safe tool -> ALLOW
# --------------------------------------------------------------------------- #
def test_autonomous_safe_tool_allowed_when_enabled(_clean_autonomy_state):
    _guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True

    decision = KillSwitchStage().evaluate(_ctx("bash", session_id=None))

    assert decision.verdict is Verdict.ALLOW


# --------------------------------------------------------------------------- #
# Human-initiated call is unaffected (no-op ALLOW), even with halt engaged
# --------------------------------------------------------------------------- #
def test_human_initiated_call_unaffected_by_halt(_clean_autonomy_state):
    guard, _cb, _settings = _clean_autonomy_state
    guard.halt(reason="test", source="unit")

    decision = KillSwitchStage().evaluate(_ctx("send_email", autonomous=False))

    assert decision.verdict is Verdict.ALLOW


def test_human_initiated_call_unaffected_when_autonomy_off(_clean_autonomy_state):
    decision = KillSwitchStage().evaluate(_ctx("bash", autonomous=False))
    assert decision.verdict is Verdict.ALLOW


# --------------------------------------------------------------------------- #
# Fail-closed
# --------------------------------------------------------------------------- #
def test_stage_fail_closed_when_guard_raises(monkeypatch, _clean_autonomy_state):
    guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True

    def boom():
        raise RuntimeError("guard exploded")

    monkeypatch.setattr(guard, "is_halted", boom)

    decision = KillSwitchStage().evaluate(_ctx("bash"))

    assert decision.verdict is Verdict.DENY
    assert "fail-closed" in decision.reason.lower()


def test_pipeline_fail_closed_to_gate_on_stage_fault(monkeypatch):
    """A stage that raises must never ALLOW; the pipeline converts it to GATE.

    We swap in a KillSwitchStage whose evaluate raises to prove the pipeline's
    fail-closed contract holds around the new stage type.
    """

    class ExplodingStage(DirectStage):
        def evaluate(self, ctx):  # type: ignore[override]
            raise RuntimeError("kaboom")

    pipeline = build_default_pipeline()
    # Replace the registered kill-switch stage with the exploding one.
    pipeline._stages = [
        ExplodingStage() if isinstance(s, DirectStage) else s for s in pipeline._stages
    ]

    decision = pipeline.evaluate(
        AdmissionContext(tool_type="bash", content="ls", session_id="s1", autonomous=True)
    )

    assert decision.verdict is Verdict.GATE


# --------------------------------------------------------------------------- #
# End-to-end through the default pipeline
# --------------------------------------------------------------------------- #
def test_default_pipeline_denies_autonomous_when_halted(_clean_autonomy_state):
    guard, _cb, settings = _clean_autonomy_state
    settings["autonomy_enabled"] = True
    guard.halt(reason="e2e", source="unit")

    pipeline = build_default_pipeline()
    decision = pipeline.evaluate(_ctx("bash"))

    assert decision.verdict is Verdict.DENY
    assert decision.stage == "autonomy_kill_switch"


def test_default_pipeline_allows_human_call_when_halted(_clean_autonomy_state):
    guard, _cb, _settings = _clean_autonomy_state
    guard.halt(reason="e2e", source="unit")

    pipeline = build_default_pipeline()
    decision = pipeline.evaluate(
        AdmissionContext(tool_type="read_file", content="notes.md", session_id="s1", autonomous=False)
    )

    # No autonomy restriction for a human call, and a genuinely read-only tool is
    # not held by the confirm gate regardless of the agent_tool_confirm setting,
    # so the call falls through the softer stages to ALLOW. (Uses read_file, not a
    # write-tier tool like bash, so the assertion can't be perturbed by confirm
    # state leaking in from another test.)
    assert decision.verdict is Verdict.ALLOW
