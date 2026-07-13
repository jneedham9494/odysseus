"""Tests for the MR-14 rebuild: tool-call VALIDATION as an admission stage plus
the unchanged tool-CAPPING selection.

The validator's real registry sources (schemas, the tool registry, the MCP map)
are heavy to import, so they are replaced with lightweight fakes injected into
``sys.modules`` before the lazy imports inside :mod:`src.tool_validation` run.
This exercises the REAL allowlist-union logic (the fix) without the tool stack.

Covered:
* an unknown / malformed tool call -> DENY
* the 5 schemaless-but-executable tools (generate_image / manage_research /
  vault_*) are NOT false-denied (the allowlist-union fix) -> ALLOW
* a valid call -> ALLOW (and the pipeline advances to later stages)
* the validation stage is registered FIRST in the default pipeline
* capping still caps a large tool set to 20
"""
from __future__ import annotations

import sys
import types

import pytest


# ---------------------------------------------------------------------------
# Fake registry modules — installed before src.tool_validation's lazy imports.
# ---------------------------------------------------------------------------
def _install_fake_registry() -> None:
    """Inject minimal fakes for the modules tool_validation imports lazily."""
    # src.tool_schemas.FUNCTION_TOOL_SCHEMAS: one schema-listed tool with a
    # required param, so we can exercise missing-required / type / enum checks.
    schemas = types.ModuleType("src.tool_schemas")
    schemas.FUNCTION_TOOL_SCHEMAS = [
        {
            "function": {
                "name": "web_search",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                        "mode": {"type": "string", "enum": ["fast", "deep"]},
                    },
                    "required": ["query"],
                },
            }
        },
    ]
    sys.modules["src.tool_schemas"] = schemas

    # src.agent_tools: TOOL_TAGS / TOOL_HANDLERS / _TOOL_NAME_MAP.
    # generate_image and manage_research are schemaless but dispatchable via
    # TOOL_TAGS; bash is a freeform tool; web_search is schema-listed too.
    agent_tools = types.ModuleType("src.agent_tools")
    agent_tools.TOOL_TAGS = {
        "bash", "python", "web_search", "generate_image", "manage_research",
    }
    agent_tools.TOOL_HANDLERS = {"bash": object(), "python": object()}
    agent_tools._TOOL_NAME_MAP = {}
    sys.modules["src.agent_tools"] = agent_tools

    # src.tool_execution._MCP_TOOL_MAP: generate_image is also MCP-mapped.
    tool_execution = types.ModuleType("src.tool_execution")
    tool_execution._MCP_TOOL_MAP = {
        "bash": ("bash", "bash"),
        "generate_image": ("image_gen", "generate_image"),
    }
    sys.modules["src.tool_execution"] = tool_execution


@pytest.fixture()
def validation():
    """Import src.tool_validation against the fake registry with clean caches."""
    _install_fake_registry()
    import src.tool_validation as tv
    tv._schema_cache = None
    tv._executable_cache = None
    yield tv
    tv._schema_cache = None
    tv._executable_cache = None


# The 5 schemaless-but-executable tools that must NOT be false-denied.
SCHEMALESS_EXECUTABLE = [
    "generate_image", "manage_research",
    "vault_search", "vault_get", "vault_unlock",
]


# ---------------------------------------------------------------------------
# validate_tool_call — the core allowlist-union logic (the fix)
# ---------------------------------------------------------------------------
def test_validate_unknown_tool_returns_error(validation):
    err = validation.validate_tool_call("totally_made_up_tool", "")
    assert err is not None
    assert "Unknown tool" in err


def test_validate_missing_tool_type_returns_error(validation):
    err = validation.validate_tool_call(None, "{}")
    assert err is not None
    assert "missing a tool type" in err


def test_validate_malformed_json_args_returns_error(validation):
    # Looks like a JSON object but does not parse -> rejected.
    err = validation.validate_tool_call("web_search", '{"query": }')
    assert err is not None
    assert "do not parse" in err


def test_validate_missing_required_param_returns_error(validation):
    err = validation.validate_tool_call("web_search", '{"limit": 5}')
    assert err is not None
    assert "Missing required parameter 'query'" in err


def test_validate_wrong_type_returns_error(validation):
    err = validation.validate_tool_call("web_search", '{"query": 123}')
    assert err is not None
    assert "must be of type string" in err


def test_validate_illegal_enum_returns_error(validation):
    err = validation.validate_tool_call(
        "web_search", '{"query": "hi", "mode": "sideways"}'
    )
    assert err is not None
    assert "must be one of" in err


def test_validate_valid_call_returns_none(validation):
    assert validation.validate_tool_call("web_search", '{"query": "hello"}') is None


def test_validate_freeform_tool_content_returns_none(validation):
    # A freeform tool (bash) whose content is not a JSON object is never faulted.
    assert validation.validate_tool_call("bash", "ls -la /tmp") is None


@pytest.mark.parametrize("tool", SCHEMALESS_EXECUTABLE)
def test_schemaless_executable_tools_not_false_denied(validation, tool):
    # THE allowlist-union fix: schemaless-but-dispatchable tools pass because
    # _executable_tool_names unions TOOL_TAGS + _MCP_TOOL_MAP + the elif-only set.
    assert validation.validate_tool_call(tool, '{"any": "args"}') is None
    assert validation.validate_tool_call(tool, "") is None


def test_executable_names_union_includes_all_dispatch_sources(validation):
    names = validation._executable_tool_names()
    assert "web_search" in names        # schema-listed
    assert "bash" in names              # TOOL_TAGS / TOOL_HANDLERS / _MCP_TOOL_MAP
    assert "generate_image" in names    # TOOL_TAGS + _MCP_TOOL_MAP, schemaless
    assert "manage_research" in names   # TOOL_TAGS, schemaless
    for vault_tool in ("vault_search", "vault_get", "vault_unlock"):
        assert vault_tool in names      # _ELIF_ONLY_DISPATCH_TOOLS
    assert "totally_made_up_tool" not in names


# ---------------------------------------------------------------------------
# ToolCallValidationStage — the admission adapter
# ---------------------------------------------------------------------------
def _make_ctx(tool_type, content="", tool_policy=None):
    from src.admission.types import AdmissionContext
    return AdmissionContext(
        tool_type=tool_type, content=content, session_id="s1",
        owner="jack", workspace=None, tool_policy=tool_policy,
    )


def test_stage_denies_unknown_tool(validation):
    from src.admission.toolcall_validation import ToolCallValidationStage
    from src.admission.types import Verdict
    decision = ToolCallValidationStage().evaluate(_make_ctx("made_up_tool"))
    assert decision.verdict is Verdict.DENY
    assert decision.stage == "toolcall_validation"
    assert "Unknown tool" in decision.reason


def test_stage_denies_malformed_args(validation):
    from src.admission.toolcall_validation import ToolCallValidationStage
    from src.admission.types import Verdict
    decision = ToolCallValidationStage().evaluate(
        _make_ctx("web_search", '{"limit": 5}')
    )
    assert decision.verdict is Verdict.DENY


def test_stage_allows_valid_call(validation):
    from src.admission.toolcall_validation import ToolCallValidationStage
    from src.admission.types import Verdict
    decision = ToolCallValidationStage().evaluate(
        _make_ctx("web_search", '{"query": "hello"}')
    )
    assert decision.verdict is Verdict.ALLOW


@pytest.mark.parametrize("tool", SCHEMALESS_EXECUTABLE)
def test_stage_allows_schemaless_executable(validation, tool):
    from src.admission.toolcall_validation import ToolCallValidationStage
    from src.admission.types import Verdict
    decision = ToolCallValidationStage().evaluate(_make_ctx(tool, "{}"))
    assert decision.verdict is Verdict.ALLOW


# ---------------------------------------------------------------------------
# Pipeline wiring — validation stage registered FIRST, DENY short-circuits
# ---------------------------------------------------------------------------
def test_validation_stage_registered_first(validation):
    from src.admission import build_default_pipeline
    pipeline = build_default_pipeline()
    assert pipeline.stage_names[0] == "toolcall_validation"


def test_pipeline_denies_unknown_before_other_stages(validation):
    from src.admission import build_default_pipeline
    from src.admission.types import Verdict
    decision = build_default_pipeline().evaluate(_make_ctx("made_up_tool", "{}"))
    assert decision.verdict is Verdict.DENY
    assert decision.stage == "toolcall_validation"


def test_pipeline_allows_valid_then_advances_to_next_stage(validation):
    # A valid call passes validation (ALLOW) so the pipeline advances; the next
    # stage (policy-block) then denies it, proving control reached later stages.
    from src.admission import build_default_pipeline
    from src.admission.types import Verdict

    class _BlockingPolicy:
        def blocks(self, tool_type):
            return True

        def reason_for(self, tool_type):
            return "policy blocks this tool"

    decision = build_default_pipeline().evaluate(
        _make_ctx("web_search", '{"query": "hi"}', tool_policy=_BlockingPolicy())
    )
    assert decision.verdict is Verdict.DENY
    assert decision.stage == "tool_policy_block"  # NOT toolcall_validation


# ---------------------------------------------------------------------------
# Tool capping — unchanged pre-prompt selection (still caps to 20)
# ---------------------------------------------------------------------------
def test_capping_caps_to_twenty():
    from src.tool_capping import cap_tools_for_request, MAX_TOOLS_PER_REQUEST
    tools = {f"tool_{i:03d}" for i in range(50)}
    capped = cap_tools_for_request("do something", tools)
    assert MAX_TOOLS_PER_REQUEST == 20
    assert len(capped) == 20
    assert capped <= tools


def test_capping_keeps_always_include_within_cap():
    from src.tool_capping import cap_tools_for_request
    tools = {f"tool_{i:03d}" for i in range(50)} | {"bash", "python"}
    capped = cap_tools_for_request(
        "run a script", tools, always_include={"bash", "python"},
    )
    assert len(capped) == 20
    assert "bash" in capped and "python" in capped


def test_capping_noop_when_under_limit():
    from src.tool_capping import cap_tools_for_request
    tools = {"bash", "python", "web_search"}
    assert cap_tools_for_request("hi", tools) == tools


def test_capping_uses_ranker_order():
    from src.tool_capping import cap_tools_for_request
    tools = {f"t{i}" for i in range(30)}

    def ranker(query, cands):
        # Force t0..t19 to the front deterministically.
        return sorted(cands, key=lambda t: int(t[1:]))

    capped = cap_tools_for_request("q", tools, limit=20, ranker=ranker)
    assert capped == {f"t{i}" for i in range(20)}
