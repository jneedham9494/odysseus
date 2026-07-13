"""Unit tests for the Phase-4 autonomy stage-machine (MR-19).

The machine is tested in ISOLATION with fakes for every injected interface
(tier-checker, kill-switch, taint gate, idempotency journal, config), so no
settings/DB/network is touched. These tests are the safety contract:

  * Ships DISABLED and at Stage 0.
  * At Stage 0, NO self-initiated action executes.
  * A HITL-forever action is refused at EVERY stage.
  * The machine can NEVER self-promote.
  * Kill-switch engaged -> nothing runs.
  * A Stage-2 reversible-internal action runs only when enabled + stage>=2 +
    not-hitl + gate-ok.
  * tainted -> high-blast-radius requires approval at EVERY stage.
  * The disabled global switch blocks everything.
"""
from __future__ import annotations

from typing import FrozenSet, Optional

import pytest

from src.autonomy_stage_machine import (
    MAX_STAGE,
    R_DISABLED,
    R_DUPLICATE,
    R_HITL_FOREVER,
    R_KILL_SWITCH,
    R_STAGE_TOO_LOW,
    R_TAINT,
    TIER_DRAFT,
    TIER_HITL,
    TIER_READ,
    TIER_WRITE,
    ActionRequest,
    CleanRun,
    StageMachine,
)


# ── Fakes ────────────────────────────────────────────────────────────────────
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
    """Maps a fixed set of tool names to tiers; unknown -> write-gated."""

    def __init__(self, mapping: Optional[dict] = None):
        self._map = mapping or {
            "read_file": TIER_READ,
            "create_document": TIER_DRAFT,
            "write_file": TIER_WRITE,
            "send_email": TIER_HITL,
            "email_self_briefing": TIER_WRITE,  # a proven-reversible ceiling tool
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
        self.records: list[tuple[str, bool]] = []

    def already_done(self, action_id: str) -> bool:
        return action_id in self.done

    def record(self, action_id: str, admitted: bool) -> None:
        self.records.append((action_id, admitted))
        if admitted:
            self.done.add(action_id)


def _machine(**overrides) -> tuple[StageMachine, dict]:
    parts = {
        "config": FakeConfig(),
        "tier_checker": FakeTiers(),
        "kill_switch": FakeKill(),
        "taint_gate": FakeTaint(),
        "journal": FakeJournal(),
    }
    parts.update(overrides)
    return StageMachine(**parts, required_clean_days=7), parts


def _req(tool="read_file", **kw) -> ActionRequest:
    return ActionRequest(action_id=kw.pop("action_id", "a1"), tool_type=tool, **kw)


# ── Ships disabled + Stage 0 ─────────────────────────────────────────────────
def test_default_config_is_disabled_and_stage_zero():
    cfg = FakeConfig()
    assert cfg.enabled() is False
    assert cfg.stage() == 0


def test_disabled_global_switch_blocks_everything():
    # Even a harmless read at a high stage is refused while autonomy is off.
    machine, _ = _machine(config=FakeConfig(enabled=False, stage=MAX_STAGE))
    d = machine.admit(_req("read_file", kind="observe"))
    assert d.admitted is False
    assert d.reason == R_DISABLED


# ── Stage 0: nothing self-initiates ──────────────────────────────────────────
@pytest.mark.parametrize(
    "tool,kind",
    [
        ("read_file", "notify"),          # notify needs stage 1
        ("create_document", None),        # draft needs stage 2
        ("write_file", None),             # write-gated never (not allowlisted)
        ("read_file", "reversible_internal"),
    ],
)
def test_stage_zero_admits_no_effectful_action(tool, kind):
    machine, _ = _machine(config=FakeConfig(enabled=True, stage=0))
    d = machine.admit(_req(tool, kind=kind))
    assert d.admitted is False


def test_stage_zero_permits_pure_observe():
    # Observe-only is exactly what Stage 0 is for.
    machine, parts = _machine(config=FakeConfig(enabled=True, stage=0))
    d = machine.admit(_req("read_file", kind="observe"))
    assert d.admitted is True
    assert ("a1", True) in parts["journal"].records


# ── HITL-forever refused at EVERY stage ──────────────────────────────────────
@pytest.mark.parametrize("stage", [0, 1, 2, 3, 4])
def test_hitl_forever_refused_at_every_stage(stage):
    # Enabled, clean gate, even on the ceiling allowlist — still refused.
    machine, _ = _machine(
        config=FakeConfig(enabled=True, stage=stage, allowlist={"send_email"})
    )
    d = machine.admit(_req("send_email", kind="ceiling"))
    assert d.admitted is False
    assert d.reason == R_HITL_FOREVER


# ── Kill-switch ──────────────────────────────────────────────────────────────
def test_kill_switch_blocks_everything():
    machine, _ = _machine(
        config=FakeConfig(enabled=True, stage=MAX_STAGE),
        kill_switch=FakeKill(engaged=True),
    )
    d = machine.admit(_req("read_file", kind="observe"))
    assert d.admitted is False
    assert d.reason == R_KILL_SWITCH


# ── Stage-2 reversible-internal action ───────────────────────────────────────
def test_reversible_internal_runs_when_enabled_and_stage_two():
    machine, parts = _machine(config=FakeConfig(enabled=True, stage=2))
    d = machine.admit(_req("create_document"))  # draft tier -> needs stage 2
    assert d.admitted is True
    assert d.tier == TIER_DRAFT
    assert d.required_stage == 2
    assert ("a1", True) in parts["journal"].records


def test_reversible_internal_refused_below_stage_two():
    machine, _ = _machine(config=FakeConfig(enabled=True, stage=1))
    d = machine.admit(_req("create_document"))
    assert d.admitted is False
    assert d.reason == R_STAGE_TOO_LOW
    assert d.required_stage == 2


def test_reversible_internal_refused_when_disabled():
    machine, _ = _machine(config=FakeConfig(enabled=False, stage=2))
    d = machine.admit(_req("create_document"))
    assert d.admitted is False
    assert d.reason == R_DISABLED


# ── Taint gate: tainted -> high blast = approval at every stage ───────────────
@pytest.mark.parametrize("stage", [0, 1, 2, 3, 4])
def test_tainted_high_blast_requires_approval_every_stage(stage):
    machine, _ = _machine(
        config=FakeConfig(enabled=True, stage=stage, allowlist={"email_self_briefing"}),
        taint_gate=FakeTaint(tainted_high=True),
    )
    d = machine.admit(_req("email_self_briefing", kind="ceiling"))
    assert d.admitted is False
    assert d.reason == R_TAINT


# ── Ceiling allowlist ────────────────────────────────────────────────────────
def test_ceiling_allowlisted_write_runs_at_stage_four():
    machine, _ = _machine(
        config=FakeConfig(enabled=True, stage=4, allowlist={"email_self_briefing"})
    )
    d = machine.admit(_req("email_self_briefing", kind="ceiling"))
    assert d.admitted is True
    assert d.tier == TIER_WRITE
    assert d.required_stage == 4


def test_write_not_in_allowlist_never_self_initiates():
    machine, _ = _machine(config=FakeConfig(enabled=True, stage=4))  # empty allowlist
    d = machine.admit(_req("write_file"))
    assert d.admitted is False  # not_self_initiable


# ── Idempotency journal ──────────────────────────────────────────────────────
def test_replay_of_journalled_action_is_refused():
    journal = FakeJournal()
    journal.done.add("dup1")
    machine, _ = _machine(config=FakeConfig(enabled=True, stage=0), journal=journal)
    d = machine.admit(_req("read_file", kind="observe", action_id="dup1"))
    assert d.admitted is False
    assert d.reason == R_DUPLICATE


def test_admit_then_replay_dedups():
    machine, parts = _machine(config=FakeConfig(enabled=True, stage=0))
    first = machine.admit(_req("read_file", kind="observe", action_id="x"))
    second = machine.admit(_req("read_file", kind="observe", action_id="x"))
    assert first.admitted is True
    assert second.admitted is False
    assert second.reason == R_DUPLICATE


# ── Promotion: NEVER self-promote ────────────────────────────────────────────
def test_admit_never_changes_stage():
    cfg = FakeConfig(enabled=True, stage=2)
    machine, _ = _machine(config=cfg)
    for _ in range(5):
        machine.admit(_req("create_document", action_id=f"n{_}"))
    assert cfg.stage() == 2  # admit must never promote


def test_promotion_requires_operator_action():
    cfg = FakeConfig(enabled=True, stage=0)
    machine, _ = _machine(config=cfg)
    # A clean run alone must not promote without an explicit operator action.
    result = machine.request_promotion(
        operator_action=False, clean_run=CleanRun(clean_days=999, violations=0)
    )
    assert result.promoted is False
    assert result.reason == "operator_action_required"
    assert cfg.stage() == 0


def test_promotion_refused_with_violations():
    cfg = FakeConfig(enabled=True, stage=0)
    machine, _ = _machine(config=cfg)
    result = machine.request_promotion(
        operator_action=True, clean_run=CleanRun(clean_days=30, violations=1)
    )
    assert result.promoted is False
    assert result.reason == "violations_present"
    assert cfg.stage() == 0


def test_promotion_refused_with_insufficient_clean_days():
    cfg = FakeConfig(enabled=True, stage=0)
    machine, _ = _machine(config=cfg)
    result = machine.request_promotion(
        operator_action=True, clean_run=CleanRun(clean_days=3, violations=0)
    )
    assert result.promoted is False
    assert result.reason == "insufficient_clean_days"
    assert cfg.stage() == 0


def test_promotion_advances_one_stage_with_operator_and_clean_run():
    cfg = FakeConfig(enabled=True, stage=0)
    machine, _ = _machine(config=cfg)
    result = machine.request_promotion(
        operator_action=True, clean_run=CleanRun(clean_days=7, violations=0)
    )
    assert result.promoted is True
    assert result.new_stage == 1
    assert cfg.stage() == 1  # advanced exactly one stage


def test_promotion_cannot_exceed_ceiling():
    cfg = FakeConfig(enabled=True, stage=MAX_STAGE)
    machine, _ = _machine(config=cfg)
    result = machine.request_promotion(
        operator_action=True, clean_run=CleanRun(clean_days=365, violations=0)
    )
    assert result.promoted is False
    assert result.reason == "already_at_ceiling"
    assert cfg.stage() == MAX_STAGE
