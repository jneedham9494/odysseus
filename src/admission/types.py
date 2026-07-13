"""Core types for the tool-admission pipeline.

A *Gate* inspects one pending tool call (an :class:`AdmissionContext`) and
returns a :class:`Decision`: ALLOW (defer to later stages), GATE (hold for human
approval), or DENY (hard block). The pipeline runs gates in a fixed order and is
fail-closed — see :mod:`src.admission.pipeline`.

This module has NO imports of production code so it can never fail to load and so
gates/tests can depend on it freely.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable


class Verdict(Enum):
    """The three outcomes of admitting a tool call.

    ALLOW means "this gate has no objection" — the pipeline continues to the next
    gate and only executes the tool if every gate allows. GATE holds the call for
    human approval. DENY hard-blocks it.
    """

    ALLOW = "allow"
    GATE = "gate"
    DENY = "deny"


@dataclass(frozen=True)
class Decision:
    """A gate's verdict plus a human-readable reason and the emitting stage name."""

    verdict: Verdict
    reason: str = ""
    stage: str = ""


def allow(stage: str = "") -> Decision:
    """No objection from this stage."""
    return Decision(Verdict.ALLOW, "", stage)


def gate(reason: str, stage: str = "") -> Decision:
    """Hold this tool call for human approval."""
    return Decision(Verdict.GATE, reason, stage)


def deny(reason: str, stage: str = "") -> Decision:
    """Hard-block this tool call."""
    return Decision(Verdict.DENY, reason, stage)


@dataclass(frozen=True)
class AdmissionContext:
    """Everything a gate needs to judge one pending tool call.

    ``tool_policy`` is the per-turn :class:`src.tool_policy.ToolPolicy` (or None);
    it is typed as ``Any`` here to keep this module import-free.
    """

    tool_type: Optional[str]
    content: Optional[str] = None
    session_id: Optional[str] = None
    owner: Optional[str] = None
    workspace: Optional[str] = None
    tool_policy: Any = None
    # True when the tool call is SELF-INITIATED by an autonomous run (task
    # scheduler / background loop) rather than driven by a live human. The
    # autonomy kill-switch stage only restricts self-initiated calls.
    autonomous: bool = False


@runtime_checkable
class Gate(Protocol):
    """One admission stage. ``name`` labels it in logs and decisions."""

    name: str

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        ...
