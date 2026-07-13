"""Safety superset: actuator tiering gates AT LEAST everything the base gates.

MR-16 makes ``src.tool_security.actuator_tier`` the sole approval classifier,
replacing base's ``tool_policy_table``-flag gate in ``pending_actions``. That is
only safe if the actuator classifier never gates LESS than the base table did.

This is a characterization test: it enumerates the REAL, live sets from
``src.tool_policy_table`` (``GATED_TOOLS`` and every tool the table classifies as
mutating = gated OR failclosed_mutator) and asserts each one resolves to a gated
actuator tier (``write-gated`` or ``hitl-forever``). If a future edit to the base
table adds a gated tool that the actuator classifier would auto-run, this fails.

It also pins the two fail-closed guarantees the classifier must keep:
unknown/malformed tools gate, and the hardcoded hitl-forever categories can never
be downgraded below hitl.
"""
from __future__ import annotations

import os
import tempfile

# pending_actions/tool_security import chain runs _init() (sqlite under DATA_DIR).
os.environ.setdefault("ODYSSEUS_DATA_DIR", tempfile.mkdtemp(prefix="superset-test-"))

import pytest

from src import tool_policy_table as tpt
from src.tool_security import (
    HITL_FOREVER_TOOLS,
    TIER_HITL,
    TIER_WRITE,
    actuator_tier,
)

GATED_TIERS = {TIER_WRITE, TIER_HITL}

# The REAL base-gated set, read live from the table (never hardcoded here): every
# tool base holds for approval (gated) or catches in the fail-closed net
# (failclosed_mutator == the "mutating" classification).
BASE_GATED_SUPERSET = (
    set(tpt.GATED_TOOLS)
    | set(tpt.FAILCLOSED_EXTRA_MUTATORS)
    | set(tpt.names_with("mutating"))
)


def test_base_gated_set_is_non_empty():
    # Guard against a vacuously-true superset test: if the table ever stopped
    # exposing gated tools, the enumeration below would prove nothing.
    assert tpt.GATED_TOOLS, "tool_policy_table.GATED_TOOLS is empty"
    assert tpt.names_with("mutating"), "no mutating tools in tool_policy_table"
    assert len(BASE_GATED_SUPERSET) >= len(tpt.GATED_TOOLS)


@pytest.mark.parametrize("tool", sorted(BASE_GATED_SUPERSET))
def test_every_base_gated_tool_is_gated_by_actuator_tier(tool):
    """The core safety property: actuator_tier never auto-runs a base-gated tool."""
    tier = actuator_tier(tool)
    assert tier in GATED_TIERS, (
        f"{tool!r} is gated/mutating in the base policy table but actuator_tier "
        f"classifies it as {tier!r} (would auto-run) - actuator gate is a SUBSET, "
        f"not a superset, of base"
    )


def test_actuator_gate_is_a_superset_as_a_whole():
    """State the property once over the whole set, not just per-parametrized case."""
    under_gated = {t: actuator_tier(t) for t in BASE_GATED_SUPERSET
                   if actuator_tier(t) not in GATED_TIERS}
    assert not under_gated, f"actuator under-gates base-gated tools: {under_gated}"


@pytest.mark.parametrize(
    "tool",
    ["totally_unknown_tool", "some_new_actuator_2027", "x", "mcp__unknown__thing"],
)
def test_unknown_tools_fail_closed(tool):
    assert actuator_tier(tool) in GATED_TIERS


@pytest.mark.parametrize("bad", [None, "", 123, object()])
def test_malformed_tool_names_fail_closed(bad):
    assert actuator_tier(bad) in GATED_TIERS  # type: ignore[arg-type]


def test_hitl_categories_cannot_be_downgraded():
    """People / deletion / physical are hardcoded hitl-forever and stay hitl
    regardless of content, and never resolve below hitl."""
    for tool in HITL_FOREVER_TOOLS:
        assert actuator_tier(tool) == TIER_HITL, tool
        # content must not be able to talk it down out of hitl
        assert actuator_tier(tool, "anything at all") == TIER_HITL, tool


def test_hitl_tools_are_a_subset_of_the_gated_superset_or_own_category():
    """Every hardcoded hitl-forever tool still gates (defense in depth): even if a
    hitl tool is not listed in the base table, actuator_tier must gate it."""
    for tool in HITL_FOREVER_TOOLS:
        assert actuator_tier(tool) in GATED_TIERS, tool
