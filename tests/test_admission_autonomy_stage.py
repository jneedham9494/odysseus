"""Tests for the autonomy admission stage (MR-19 as an admission Gate).

These verify the *integration* contract of :class:`AutonomyStageStage` — how the
Phase-4 stage-machine maps onto the ordered, fail-closed admission pipeline:

  * Human-initiated calls (``autonomous`` False) are a no-op ALLOW, unaffected.
  * At Stage 0, no self-initiated action is admitted (all GATE).
  * A HITL-forever self-initiated action is GATEd at EVERY stage.
  * The disabled global switch blocks (GATE) every self-initiated action.
  * The stage can never self-promote (admit never mutates the stage).
  * A permitted self-initiated action (enabled + stage high enough + clean gate)
    is ALLOWed.

The stage-machine is built from in-memory fakes so no settings/DB/network runs.
"""
from __future__ import annotations

from typing import FrozenSet, Optional

import pytest

from src.admission.autonomy_stage import AutonomyStageStage
from src.admission.types import AdmissionContext, Verdict
from src.autonomy_stage_machine import (
    MAX_STAGE,
    TIER_DRAFT,
    TIER_HITL,
    TIER_READ,
    TIER_WRITE,
    StageMachine,
)


# ── Fakes (mirror the isolated FSM tests) ────────────────────────────────────
class FakeConfig:
    def __init__(self, enabled=False, stage=0, allowlist: Optional[set] = None):
        self._enabled = enabled
        self._stage = stage
        self._allowlist = frozenset(allowlist or set())

    def enabled(self) -> bool:
        return self._enabled

    def stage(self) -> int:
        return self._stage

    def ceiling_allowlist(self) -> FrozenSet[str]:
        return self._allowlist

    def set_stage(self, stage: int) -> None:
        self._stage = stage


class FakeTiers:
    def __init__(self, mapping: Optional[dict] = None):
        self._map = mapping or {
            "read_file": TIER_READ,
            "create_document": TIER_DRAFT,
            "write_file": TIER_WRITE,
            "send_email": TIER_HITL,
        }

    def tier(self, tool_type, content=None) -> str:
        return self._map.get(tool_type, TIER_WRITE)


class FakeKill:
    def __init__(self, engaged=False):
        self._engaged = engaged

    def engaged(self) -> bool:
        return self._engaged


class FakeTaint:
    def __init__(self, tainted_high=False):
        self._tainted_high = tainted_high

    def requires_taint_approval(self, session_id, tool_type, content=None) -> bool:
        return self._tainted_high


class FakeJournal:
    def __init__(self):
        self.done: set[str] = set()

    def already_done(self, action_id: str) -> bool:
        return action_id in self.done

    def record(self, action_id: str, admitted: bool) -> None:
        if admitted:
            self.done.add(action_id)


def _stage(config: FakeConfig, **overrides) -> AutonomyStageStage:
    parts = {
        "config": config,
        "tier_checker": FakeTiers(),
        "kill_switch": FakeKill(),
        "taint_gate": FakeTaint(),
        "journal": FakeJournal(),
    }
    parts.update(overrides)
    machine = StageMachine(**parts, required_clean_days=7)
    return AutonomyStageStage(machine=machine)


def _ctx(tool="read_file", autonomous=True, **kw) -> AdmissionContext:
    return AdmissionContext(
        tool_type=tool,
        content=kw.get("content"),
        session_id=kw.get("session_id", "s1"),
        autonomous=autonomous,
    )


# ── Human-initiated calls unaffected ─────────────────────────────────────────
def test_human_initiated_call_is_noop_allow():
    # Autonomy fully off + a HITL tool: a HUMAN call must still ALLOW here — the
    # autonomy stage does not touch human-initiated actions.
    stage = _stage(FakeConfig(enabled=False, stage=0))
    d = stage.evaluate(_ctx("send_email", autonomous=False))
    assert d.verdict is Verdict.ALLOW


def test_human_initiated_call_allows_even_when_stage_would_refuse():
    stage = _stage(FakeConfig(enabled=True, stage=0))
    d = stage.evaluate(_ctx("write_file", autonomous=False))
    assert d.verdict is Verdict.ALLOW


# ── Stage 0: nothing self-initiates ──────────────────────────────────────────
@pytest.mark.parametrize("tool", ["create_document", "write_file", "send_email"])
def test_stage_zero_gates_self_initiated_effectful_action(tool):
    stage = _stage(FakeConfig(enabled=True, stage=0))
    d = stage.evaluate(_ctx(tool))
    assert d.verdict is Verdict.GATE


def test_stage_zero_allows_self_initiated_pure_observe():
    stage = _stage(FakeConfig(enabled=True, stage=0))
    d = stage.evaluate(_ctx("read_file"))  # read tier -> observe, stage 0 ok
    assert d.verdict is Verdict.ALLOW


# ── Disabled global switch blocks everything ─────────────────────────────────
def test_disabled_global_switch_gates_self_initiated():
    # Even a harmless read at the ceiling stage is GATEd while autonomy is off.
    stage = _stage(FakeConfig(enabled=False, stage=MAX_STAGE))
    d = stage.evaluate(_ctx("read_file"))
    assert d.verdict is Verdict.GATE


# ── HITL-forever refused at EVERY stage ──────────────────────────────────────
@pytest.mark.parametrize("stage_num", [0, 1, 2, 3, 4])
def test_hitl_forever_gated_at_every_stage(stage_num):
    stage = _stage(
        FakeConfig(enabled=True, stage=stage_num, allowlist={"send_email"})
    )
    d = stage.evaluate(_ctx("send_email"))
    assert d.verdict is Verdict.GATE


# ── Taint gate: tainted -> high blast requires approval ───────────────────────
@pytest.mark.parametrize("stage_num", [0, 2, 4])
def test_tainted_high_blast_gated(stage_num):
    stage = _stage(
        FakeConfig(enabled=True, stage=stage_num),
        taint_gate=FakeTaint(tainted_high=True),
    )
    d = stage.evaluate(_ctx("read_file"))
    assert d.verdict is Verdict.GATE


# ── Permitted self-initiated action is ALLOWed ───────────────────────────────
def test_permitted_reversible_internal_allowed_at_stage_two():
    stage = _stage(FakeConfig(enabled=True, stage=2))
    d = stage.evaluate(_ctx("create_document", content="draft body"))
    assert d.verdict is Verdict.ALLOW


# ── Cannot self-promote: repeated admits never raise the stage ───────────────
def test_stage_never_self_promotes():
    cfg = FakeConfig(enabled=True, stage=1)
    stage = _stage(cfg)
    for i in range(5):
        stage.evaluate(_ctx("create_document", content=f"body-{i}"))
    assert cfg.stage() == 1  # admit must never promote the stage
