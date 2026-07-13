"""Tool-admission gate: one ordered, fail-closed, testable pipeline.

This package is the enforced boundary that decides, for every pending tool call,
whether to ALLOW it, GATE it for human approval, or DENY (hard-block) it. It
replaces the inline ``if/elif/else`` that lived in ``stream_agent_loop``.

Public surface:

* :func:`build_default_pipeline` — the pipeline wired into the agent loop.
* :class:`AdmissionPipeline` — runner; ``.register_stage(...)`` is the extension
  seam for future gates (autonomy, toolcall-validate, llama-guard).
* :class:`AdmissionContext`, :class:`Decision`, :class:`Verdict` — the data model.
* :class:`ToolPolicyView` — the single read surface over the scattered tier lists.
* ``requires_confirm_approval_failclosed`` / ``requires_taint_approval_safe`` —
  the canonical fail-closed checks the agent loop delegates to.
"""
from __future__ import annotations

from src.admission.autonomy_stage import AutonomyStageStage
from src.admission.kill_switch import KillSwitchStage
from src.admission.pipeline import AdmissionPipeline, build_default_pipeline
from src.admission.policy_view import ToolPolicyView
from src.admission.stages import (
    ConfirmApprovalStage,
    PolicyBlockStage,
    TaintApprovalStage,
    requires_confirm_approval_failclosed,
    requires_taint_approval_safe,
)
from src.admission.toolcall_validation import ToolCallValidationStage
from src.admission.types import (
    AdmissionContext,
    Decision,
    Gate,
    Verdict,
    allow,
    deny,
    gate,
)

__all__ = [
    "AdmissionPipeline",
    "build_default_pipeline",
    "ToolPolicyView",
    "PolicyBlockStage",
    "KillSwitchStage",
    "TaintApprovalStage",
    "ConfirmApprovalStage",
    "ToolCallValidationStage",
    "AutonomyStageStage",
    "requires_confirm_approval_failclosed",
    "requires_taint_approval_safe",
    "AdmissionContext",
    "Decision",
    "Gate",
    "Verdict",
    "allow",
    "deny",
    "gate",
]
