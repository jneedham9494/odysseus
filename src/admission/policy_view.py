"""Single read surface over the scattered tool tier / mutator lists.

Today the risk classification of a tool is spread across three modules:

* ``src.pending_actions`` — ``DEFAULT_GATED_TOOLS``, ``is_mutating_tool``,
  ``_is_write_api_call`` (the auto-confirm approval tier).
* ``src.context_taint`` — ``_CREDENTIALED_MUTATORS``, ``_UNTRUSTED_SOURCE_TOOLS``
  (the taint / EchoLeak tier).
* ``src.tool_security`` — ``NON_ADMIN_BLOCKED_TOOLS``, ``_PLAN_MODE_KNOWN_MUTATORS``
  (the public-user / plan-mode tiers).

This class does NOT move those lists — it only centralizes the READ so there is
one query surface. **SEAM:** a later MR consolidates the underlying lists behind
these methods (or a unified table) without touching callers.

Every method lazy-imports its source module inside the call so that test
monkeypatching of the underlying functions is observed, and so a broken source
module can't stop this module from importing.
"""
from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ToolPolicyView:
    """One query surface over the tool tier / mutator lists (read-only)."""

    # --- auto-confirm approval tier (pending_actions) ---

    @staticmethod
    def requires_confirm_approval(tool_type: Optional[str], content: Optional[str]) -> bool:
        """Full ``agent_tool_confirm`` policy: is this call queued for approval?"""
        from src.pending_actions import requires_approval

        return bool(requires_approval(tool_type, content))

    @staticmethod
    def confirm_enabled() -> bool:
        """Is the auto-confirm approval gate switched on at all?"""
        from src.pending_actions import confirm_enabled

        return bool(confirm_enabled())

    @staticmethod
    def is_mutating(tool_type: Optional[str], content: Optional[str]) -> bool:
        """Static (settings/DB-free) mutator classification. Unknown → mutating."""
        from src.pending_actions import is_mutating_tool

        return bool(is_mutating_tool(tool_type, content))

    # --- taint / EchoLeak tier (context_taint) ---

    @staticmethod
    def requires_taint_approval(
        session_id: Optional[str], tool_type: Optional[str], content: Optional[str]
    ) -> bool:
        """A credentialed action in a tainted session must be human-approved."""
        from src.context_taint import requires_taint_approval

        return bool(requires_taint_approval(session_id, tool_type, content))

    @staticmethod
    def is_credentialed_mutator(tool_type: Optional[str], content: Optional[str]) -> bool:
        from src.context_taint import is_credentialed_mutator

        return bool(is_credentialed_mutator(tool_type, content))

    @staticmethod
    def is_untrusted_source(tool_type: Optional[str]) -> bool:
        from src.context_taint import is_untrusted_source

        return bool(is_untrusted_source(tool_type))

    # --- public-user / plan-mode tiers (tool_security) ---

    @staticmethod
    def is_public_blocked(tool_type: Optional[str]) -> bool:
        from src.tool_security import is_public_blocked_tool

        return bool(is_public_blocked_tool(tool_type))
