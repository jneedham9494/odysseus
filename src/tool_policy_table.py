"""Single audited source of truth for per-tool risk classification.

Historically the "risk / tier of a tool" was declared in ~5 places that had to
be kept manually in sync:

* ``src.pending_actions`` — ``DEFAULT_GATED_TOOLS``, ``_FAILCLOSED_EXTRA_MUTATORS``,
  ``_METHOD_AWARE_TOOLS``, ``GATED_MCP_PREFIXES`` (auto-confirm approval tier).
* ``src.tool_security`` — ``NON_ADMIN_BLOCKED_TOOLS``, ``_PLAN_MODE_KNOWN_MUTATORS``
  (public-user / plan-mode tiers).
* ``src.context_taint`` — ``_CREDENTIALED_MUTATORS``, ``_UNTRUSTED_SOURCE_TOOLS``,
  ``_METHOD_AWARE``, ``_UNTRUSTED_PREFIXES`` (taint / EchoLeak tier).

This module makes that classification declarative: one table (``_TABLE`` for exact
tool names, ``_PATTERN_TABLE`` for name prefixes) declares each tool's ``tier`` plus
its risk flags. The scattered constants above now DERIVE from this table (see the
``*_TOOLS`` / ``*_PREFIXES`` frozensets below), so every tool's risk is auditable in
one place and stays in sync by construction.

Behaviour is unchanged: the derived sets are byte-for-byte equal to the literals
they replaced (proven by ``tests/test_tool_policy_table.py``). ``tier`` is new
advisory metadata that no gate consumes yet — it is the seam the actuator-tiering
MR extends.

Fail-closed: ``get_policy`` resolves an unknown / malformed tool name to the
most-restrictive policy (every flag set, highest tier).
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from enum import IntEnum
from typing import Dict, FrozenSet, Optional, Tuple

# Boolean flag columns of the policy table. "mutating" is DERIVED (see
# ``ToolPolicy.mutating``) and intentionally excluded from the stored columns.
_FLAG_FIELDS: Tuple[str, ...] = (
    "gated",
    "failclosed_mutator",
    "non_admin_blocked",
    "plan_mode_mutator",
    "credentialed_mutator",
    "untrusted_source",
    "method_aware",
)


class ToolTier(IntEnum):
    """Ordered risk tier by blast radius. Higher = more dangerous.

    Advisory metadata only — no gate consumes this yet. Unknown tools resolve to
    the highest tier (fail-closed). This is the seam the actuator-tiering MR
    extends.
    """

    READ = 0          # read-only / inspection
    WRITE = 1         # local mutation (files, docs, sessions, memory)
    EXTERNAL = 2      # acts on the outside world with the user's credentials
    ADMIN = 3         # server / infra / config control, secrets, model serving


@dataclass(frozen=True)
class ToolPolicy:
    """Risk classification of one tool (or one name-prefix pattern).

    Each boolean maps to exactly one historically-scattered list, so the old
    constants derive from this table without any behaviour change.
    """

    tier: ToolTier
    gated: bool = False               # DEFAULT_GATED_TOOLS (auto-confirm gate)
    failclosed_mutator: bool = False  # _FAILCLOSED_EXTRA_MUTATORS (static net)
    non_admin_blocked: bool = False   # NON_ADMIN_BLOCKED_TOOLS (public-user gate)
    plan_mode_mutator: bool = False   # _PLAN_MODE_KNOWN_MUTATORS (plan-mode backstop)
    credentialed_mutator: bool = False  # _CREDENTIALED_MUTATORS (taint gate)
    untrusted_source: bool = False    # _UNTRUSTED_SOURCE_TOOLS (taint source)
    method_aware: bool = False        # gate on HTTP method, not unconditionally

    @property
    def mutating(self) -> bool:
        """Static mutator classification = gated OR failclosed_mutator.

        Mirrors ``pending_actions.is_mutating_tool``'s exact-name check.
        """
        return self.gated or self.failclosed_mutator


def _p(tier: ToolTier, *flags: str) -> ToolPolicy:
    """Build a ToolPolicy from a tier and the names of the flags that are True."""
    unknown = set(flags) - set(_FLAG_FIELDS)
    if unknown:
        raise ValueError(f"unknown policy flags: {sorted(unknown)}")
    return ToolPolicy(tier=tier, **{name: True for name in flags})


# ── Exact-name policy table ──────────────────────────────────────────────────
# One row per tool. List only the True flags; everything else defaults False.
_TABLE: Dict[str, ToolPolicy] = {
    # -- read-only / inspection (public-user blocked but never mutating) --
    "read_file": _p(ToolTier.READ, "non_admin_blocked"),
    "grep": _p(ToolTier.READ, "non_admin_blocked"),
    "glob": _p(ToolTier.READ, "non_admin_blocked"),
    "ls": _p(ToolTier.READ, "non_admin_blocked"),
    "get_workspace": _p(ToolTier.READ, "non_admin_blocked"),
    "search_chats": _p(ToolTier.READ, "non_admin_blocked"),
    "list_emails": _p(ToolTier.READ, "non_admin_blocked"),
    "read_email": _p(ToolTier.READ, "non_admin_blocked"),
    "resolve_contact": _p(ToolTier.READ, "non_admin_blocked"),
    "vault_search": _p(ToolTier.READ, "non_admin_blocked"),
    "vault_get": _p(ToolTier.READ, "non_admin_blocked"),
    # untrusted external content — the taint SOURCE, not a mutating action
    "web_fetch": _p(ToolTier.READ, "untrusted_source"),
    "web_search": _p(ToolTier.READ, "untrusted_source"),
    # SearXNG MCP tool: read-only web results are attacker-controllable, so it
    # is an untrusted taint source (registered by exact qualified name).
    "mcp__searxng__web_search": _p(ToolTier.READ, "untrusted_source"),

    # -- local mutation (WRITE tier) --
    "write_file": _p(ToolTier.WRITE, "gated", "non_admin_blocked", "plan_mode_mutator"),
    "edit_file": _p(ToolTier.WRITE, "gated", "non_admin_blocked"),
    "delete_file": _p(ToolTier.WRITE, "failclosed_mutator"),
    "move_file": _p(ToolTier.WRITE, "failclosed_mutator"),
    "create_document": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "edit_document": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "update_document": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "suggest_document": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "manage_documents": _p(ToolTier.WRITE, "non_admin_blocked", "plan_mode_mutator"),
    "create_session": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "manage_session": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "send_to_session": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "pipeline": _p(ToolTier.WRITE, "plan_mode_mutator"),
    "manage_memory": _p(ToolTier.WRITE, "non_admin_blocked", "plan_mode_mutator"),
    "manage_skills": _p(ToolTier.WRITE, "non_admin_blocked", "plan_mode_mutator"),
    "manage_tasks": _p(ToolTier.WRITE, "non_admin_blocked", "plan_mode_mutator"),
    "manage_notes": _p(ToolTier.WRITE, "plan_mode_mutator"),

    # -- outside-world actions with the user's credentials (EXTERNAL tier) --
    "send_email": _p(ToolTier.EXTERNAL, "failclosed_mutator", "non_admin_blocked",
                     "plan_mode_mutator", "credentialed_mutator"),
    "reply_to_email": _p(ToolTier.EXTERNAL, "failclosed_mutator", "non_admin_blocked",
                         "plan_mode_mutator", "credentialed_mutator"),
    "bulk_email": _p(ToolTier.EXTERNAL, "failclosed_mutator", "plan_mode_mutator",
                     "credentialed_mutator"),
    "delete_email": _p(ToolTier.EXTERNAL, "plan_mode_mutator"),
    "archive_email": _p(ToolTier.EXTERNAL, "plan_mode_mutator"),
    "mark_email_read": _p(ToolTier.EXTERNAL, "plan_mode_mutator"),
    "manage_calendar": _p(ToolTier.EXTERNAL, "gated", "non_admin_blocked", "plan_mode_mutator"),
    "manage_contact": _p(ToolTier.EXTERNAL, "gated", "non_admin_blocked", "plan_mode_mutator"),
    "ui_control": _p(ToolTier.EXTERNAL, "gated", "plan_mode_mutator"),
    "generate_image": _p(ToolTier.EXTERNAL, "gated", "plan_mode_mutator"),
    "edit_image": _p(ToolTier.EXTERNAL, "gated", "plan_mode_mutator"),
    "trigger_research": _p(ToolTier.EXTERNAL, "plan_mode_mutator"),
    "manage_research": _p(ToolTier.EXTERNAL, "plan_mode_mutator"),
    # HTTP-method-aware: gated only for write methods (POST/PUT/PATCH/DELETE)
    "api_call": _p(ToolTier.EXTERNAL, "non_admin_blocked", "plan_mode_mutator", "method_aware"),
    "app_api": _p(ToolTier.EXTERNAL, "non_admin_blocked", "plan_mode_mutator", "method_aware"),

    # -- server / infra / config control (ADMIN tier) --
    "bash": _p(ToolTier.ADMIN, "gated", "non_admin_blocked", "plan_mode_mutator"),
    "python": _p(ToolTier.ADMIN, "gated", "non_admin_blocked", "plan_mode_mutator"),
    "manage_bg_jobs": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "manage_endpoints": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "manage_mcp": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "manage_webhooks": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "manage_tokens": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "manage_settings": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "vault_unlock": _p(ToolTier.ADMIN, "non_admin_blocked"),
    "download_model": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "serve_model": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "serve_preset": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "stop_served_model": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "cancel_download": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
    "adopt_served_model": _p(ToolTier.ADMIN, "non_admin_blocked", "plan_mode_mutator"),
}


# ── Name-prefix policy table ─────────────────────────────────────────────────
# Browser-automation tools register as e.g. "browser_navigate" / "playwright_click":
# gated + a taint source + a credentialed mutator (they can submit/exfil). MCP tools
# register under the "mcp__" namespace and are blocked for public users.
_PATTERN_TABLE: Dict[str, ToolPolicy] = {
    "browser_": _p(ToolTier.EXTERNAL, "gated", "untrusted_source", "credentialed_mutator"),
    "playwright_": _p(ToolTier.EXTERNAL, "gated", "untrusted_source", "credentialed_mutator"),
    "mcp__": _p(ToolTier.ADMIN, "non_admin_blocked"),
}


# The most-restrictive policy. Unknown / malformed tool names resolve here so a
# new or unrecognised tool is treated as maximally dangerous (fail-closed).
_MOST_RESTRICTIVE = ToolPolicy(
    tier=ToolTier.ADMIN,
    gated=True,
    failclosed_mutator=True,
    non_admin_blocked=True,
    plan_mode_mutator=True,
    credentialed_mutator=True,
    untrusted_source=True,
    method_aware=False,  # unconditional gating is stricter than method-conditional
)


def get_policy(tool_type: Optional[str]) -> ToolPolicy:
    """Resolve a tool name to its policy. Fail-closed: unknown → most-restrictive.

    Exact-name matches win over prefix matches. A ``None`` / empty / non-string
    name (a malformed call) also resolves to the most-restrictive policy.
    """
    if not tool_type or not isinstance(tool_type, str):
        return _MOST_RESTRICTIVE
    exact = _TABLE.get(tool_type)
    if exact is not None:
        return exact
    for prefix, policy in _PATTERN_TABLE.items():
        if tool_type.startswith(prefix):
            return policy
    return _MOST_RESTRICTIVE


def names_with(flag: str) -> FrozenSet[str]:
    """Exact tool names whose policy has ``flag`` set (e.g. ``"gated"``)."""
    if flag != "mutating" and flag not in _FLAG_FIELDS:
        raise ValueError(f"unknown policy flag: {flag!r}")
    return frozenset(name for name, p in _TABLE.items() if getattr(p, flag))


def prefixes_with(flag: str) -> Tuple[str, ...]:
    """Name prefixes whose pattern policy has ``flag`` set (insertion order)."""
    if flag != "mutating" and flag not in _FLAG_FIELDS:
        raise ValueError(f"unknown policy flag: {flag!r}")
    return tuple(pre for pre, p in _PATTERN_TABLE.items() if getattr(p, flag))


# ── Derived classification sets (the single source the old lists read) ────────
GATED_TOOLS: FrozenSet[str] = names_with("gated")
FAILCLOSED_EXTRA_MUTATORS: FrozenSet[str] = names_with("failclosed_mutator")
NON_ADMIN_BLOCKED_TOOLS: FrozenSet[str] = names_with("non_admin_blocked")
PLAN_MODE_MUTATORS: FrozenSet[str] = names_with("plan_mode_mutator")
CREDENTIALED_MUTATORS: FrozenSet[str] = names_with("credentialed_mutator")
UNTRUSTED_SOURCE_TOOLS: FrozenSet[str] = names_with("untrusted_source")
METHOD_AWARE_TOOLS: FrozenSet[str] = names_with("method_aware")

GATED_PREFIXES: Tuple[str, ...] = prefixes_with("gated")
UNTRUSTED_PREFIXES: Tuple[str, ...] = prefixes_with("untrusted_source")
NON_ADMIN_BLOCKED_PREFIXES: Tuple[str, ...] = prefixes_with("non_admin_blocked")


def _validate() -> None:
    """Import-time invariants (fail fast on a malformed table)."""
    valid = {f.name for f in fields(ToolPolicy)}
    assert valid == {"tier", *_FLAG_FIELDS}, "ToolPolicy fields drifted from _FLAG_FIELDS"
    # gated ⟹ mutating (the auto-confirm gate is a subset of static mutators).
    assert GATED_TOOLS <= names_with("mutating"), "a gated tool must be mutating"
    assert _MOST_RESTRICTIVE.mutating, "fail-closed default must classify as mutating"


_validate()
