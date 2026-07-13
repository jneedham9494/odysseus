"""Tool-call validation admission stage (MR-14).

Registered FIRST in the pipeline: before policy, taint, or approval get a say, a
structurally-malformed or genuinely-unknown tool call is hard-blocked (DENY) so
it can never reach a real-world action. A well-formed call ALLOWs, letting the
later stages (policy-block, taint, confirm-approval) run.

The heavy lifting — schema lookup, the executable-tool allowlist union that keeps
schemaless-but-real tools (generate_image, manage_research, vault_*) from being
false-denied — lives in :mod:`src.tool_validation`. This stage is a thin,
fail-closed adapter from that validator to a :class:`Decision`.
"""
from __future__ import annotations

import logging

from src.admission.types import AdmissionContext, Decision, allow, deny

logger = logging.getLogger(__name__)


class ToolCallValidationStage:
    """DENY a malformed/unknown tool call; ALLOW a well-formed one.

    Fail-closed: the pipeline turns any exception into GATE, but this stage's own
    contract is that a call it is CONFIDENT is malformed is denied, and anything
    it cannot confidently fault (freeform bash/python/query content, MCP/email
    tools validated elsewhere, schemaless-but-dispatchable tools) is allowed
    through to the downstream gates rather than blocked here.
    """

    name = "toolcall_validation"

    def evaluate(self, ctx: AdmissionContext) -> Decision:
        # Imported lazily: tool_validation pulls in the tool registry/schemas,
        # and this keeps the admission package cheap to import.
        from src.tool_validation import validate_tool_call

        error = validate_tool_call(ctx.tool_type, ctx.content)
        if error:
            logger.warning(
                "Rejected malformed tool call at admission: %s: %s",
                ctx.tool_type, error,
            )
            return deny(error, self.name)
        return allow(self.name)
