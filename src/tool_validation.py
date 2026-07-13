"""
tool_validation.py

Schema-validate agent tool calls against FUNCTION_TOOL_SCHEMAS. A malformed call
(unknown tool, missing required parameter, wrong type, illegal enum value, or
non-parsing JSON arguments) is REJECTED so the admission pipeline can DENY it —
never silently execute it — and the model is reprompted with the specific error.

This is a fail-closed boundary: the validator only flags calls it is confident
are malformed, so legitimate calls are never blocked, but a call that clearly
violates its schema cannot slip through to a real-world action.

The admission-stage entry point is :func:`validate_tool_call`, which takes the
``tool_type`` / ``content`` of an already-parsed tool block (an
:class:`src.admission.AdmissionContext`) and returns an error string or None.
"""

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# JSON-schema primitive type -> Python type(s). bool is handled specially
# because Python's bool is a subclass of int.
_JSON_PY_TYPES: Dict[str, Any] = {
    "string": str,
    "number": (int, float),
    "integer": int,
    "boolean": bool,
    "array": list,
    "object": dict,
}

# Email tools are implemented as MCP (mcp__email__*) and validated by the MCP
# layer, not by FUNCTION_TOOL_SCHEMAS. Recognise them so we pass them through
# instead of rejecting them as "unknown".
_BUILTIN_EMAIL_TOOLS = frozenset({
    "list_email_accounts", "send_email", "list_emails", "read_email",
    "reply_to_email", "archive_email", "delete_email", "mark_email_read",
    "bulk_email", "download_attachment",
})

# Tools dispatched ONLY by tool_execution's elif-chain — they have no
# FUNCTION_TOOL_SCHEMAS entry, are not in _MCP_TOOL_MAP, and are not registered
# in agent_tools.TOOL_HANDLERS / TOOL_TAGS. _executable_tool_names() unions this
# set into its allowlist so the unknown-tool guard does not fail-close these
# real, dispatchable tools as "unknown". Keep it in sync with the elif branches
# in tool_execution._execute_tool_block_impl (vault_search/vault_get/vault_unlock).
# (Defined here rather than in tool_execution.py, which is already at its
# meaningful-line ceiling; this module is its only consumer.)
_ELIF_ONLY_DISPATCH_TOOLS = frozenset({
    "vault_search", "vault_get", "vault_unlock",
})

# Tools whose block *content* is a raw freeform payload, NOT a JSON args object.
# tool_schemas.function_call_to_tool_block serialises these tools' arguments into
# plain text (e.g. python -> args["code"], bash -> args["command"], the document/
# session/memory tools -> concatenated fields), so the content the admission
# boundary sees is user/model code or prose, not a `{...}` args map. That payload
# may itself be a brace-delimited literal (a Python set/dict, a JSON file body, a
# shell heredoc), which the JSON-arg heuristic below would otherwise mis-read and
# false-deny. These tools are therefore never arg-validated here — matching this
# module's contract that freeform bash/python/query content is left alone. Keep
# in sync with the raw-text branches of function_call_to_tool_block. (web_search
# is intentionally absent: its content is either a bare query — which is not
# brace-delimited — or a genuine `{"query", "time_filter"}` args object we DO want
# to validate.)
_FREEFORM_CONTENT_TOOLS = frozenset({
    "bash", "python", "get_workspace", "read_file", "write_file",
    "create_document", "edit_document", "suggest_document", "update_document",
    "search_chats", "chat_with_model", "create_session", "list_sessions",
    "send_to_session", "manage_session", "manage_memory", "list_models",
    "ui_control", "ask_teacher",
})

_schema_cache: Optional[Dict[str, Dict[str, Any]]] = None
_executable_cache: Optional[frozenset] = None


def _executable_tool_names() -> frozenset:
    """Every tool name the execution boundary can actually dispatch.

    FUNCTION_TOOL_SCHEMAS is only the schema-listed SUBSET; the executor
    (tool_execution._execute_tool_block_impl) dispatches a superset — legacy
    MCP-mapped tools (_MCP_TOOL_MAP), registry tools (TOOL_HANDLERS / TOOL_TAGS),
    and a few handled solely by its elif-chain (_ELIF_ONLY_DISPATCH_TOOLS, e.g.
    the vault_* tools). Unioning every dispatch source is what lets the
    unknown-tool guard stay fail-closed on genuinely-unknown tools WITHOUT
    false-rejecting real ones (generate_image, manage_research, vault_*). Built
    once and cached; imported lazily to keep this module cheap and avoid a
    tool_execution import cycle.
    """
    global _executable_cache
    if _executable_cache is None:
        names = set(_schema_index().keys())
        from src.agent_tools import TOOL_HANDLERS, TOOL_TAGS
        from src.tool_execution import _MCP_TOOL_MAP
        names |= set(TOOL_TAGS)
        names |= set(TOOL_HANDLERS.keys())
        names |= set(_MCP_TOOL_MAP.keys())
        names |= set(_ELIF_ONLY_DISPATCH_TOOLS)
        _executable_cache = frozenset(names)
    return _executable_cache


def _schema_index() -> Dict[str, Dict[str, Any]]:
    """Map tool name -> its JSON-schema `parameters` object.

    Built once from FUNCTION_TOOL_SCHEMAS and cached. Imported lazily so this
    module stays cheap to import (tool_schemas pulls in the tool registry).
    """
    global _schema_cache
    if _schema_cache is None:
        from src.tool_schemas import FUNCTION_TOOL_SCHEMAS
        index: Dict[str, Dict[str, Any]] = {}
        for entry in FUNCTION_TOOL_SCHEMAS:
            fn = entry.get("function") if isinstance(entry, dict) else None
            if not isinstance(fn, dict):
                continue
            name = fn.get("name")
            params = fn.get("parameters") or {}
            if isinstance(name, str) and name:
                index[name] = params if isinstance(params, dict) else {}
        _schema_cache = index
    return _schema_cache


def _canonical_name(name: str) -> str:
    """Resolve a model-emitted tool name to its canonical schema name."""
    # Import via agent_tools (which re-exports the map) rather than tool_parsing
    # directly: tool_parsing <-> agent_tools is a circular pair that only
    # resolves when agent_tools is imported first, so go through it.
    from src.agent_tools import _TOOL_NAME_MAP
    return _TOOL_NAME_MAP.get(name, name)


def _type_matches(expected: str, value: Any) -> bool:
    """Return True if *value* satisfies the JSON-schema primitive *expected*."""
    py = _JSON_PY_TYPES.get(expected)
    if py is None:
        # Unknown/compound type declaration — don't second-guess it.
        return True
    if expected == "boolean":
        return isinstance(value, bool)
    if expected in ("integer", "number"):
        # bool is a Python int subclass but is not a JSON number here.
        return isinstance(value, py) and not isinstance(value, bool)
    return isinstance(value, py)


def validate_function_args(name: str, args: Dict[str, Any]) -> Optional[str]:
    """Validate an already-parsed args dict for *name* against its schema.

    Returns a specific human-readable error string, or None when the call is
    valid (or when the tool has no FUNCTION_TOOL_SCHEMAS entry to check against,
    e.g. MCP/email tools that are validated elsewhere).
    """
    canonical = _canonical_name(name)
    if canonical.startswith("mcp__") or canonical in _BUILTIN_EMAIL_TOOLS \
            or name in _BUILTIN_EMAIL_TOOLS:
        return None  # validated by the MCP/email layer, not by us

    schema = _schema_index().get(canonical)
    if schema is None:
        # No JSON-schema to check args against. Only reject if the tool is not
        # dispatchable at all; a schemaless-but-executable tool (generate_image,
        # manage_research, vault_*) is a valid call we simply can't arg-check.
        if canonical in _executable_tool_names():
            return None
        return f"Unknown tool '{name}'. It is not one of the available tools."

    if not isinstance(args, dict):
        return (
            f"Arguments for '{name}' must be a JSON object, "
            f"got {type(args).__name__}."
        )

    properties = schema.get("properties") or {}
    required = schema.get("required") or []

    for field in required:
        if field not in args:
            return f"Missing required parameter '{field}' for '{name}'."

    for key, value in args.items():
        spec = properties.get(key)
        if not isinstance(spec, dict) or value is None:
            # Extra/unknown keys are tolerated; models often add harmless ones.
            continue
        expected_type = spec.get("type")
        if isinstance(expected_type, str) and not _type_matches(expected_type, value):
            return (
                f"Parameter '{key}' for '{name}' must be of type {expected_type}, "
                f"got {type(value).__name__}."
            )
        enum = spec.get("enum")
        if isinstance(enum, list) and value not in enum:
            allowed = ", ".join(repr(e) for e in enum)
            return (
                f"Parameter '{key}' for '{name}' must be one of [{allowed}], "
                f"got {value!r}."
            )
    return None


def validate_tool_call(tool_type: Optional[str], content: Optional[str]) -> Optional[str]:
    """Admission-boundary guard for a pending tool call (from ANY parse path).

    Conservative by design: it only validates a call it can read confidently —
    an unknown tool name, or a block whose content is a JSON object (the shape
    most structured tools use). Freeform text tools (bash command, python code,
    a bare query) are left alone so this guard never false-rejects them. Returns
    a specific error string, or None when the call is acceptable.
    """
    content = content or ""

    if not isinstance(tool_type, str) or not tool_type:
        return "Tool call is missing a tool type."

    canonical = _canonical_name(tool_type)
    if canonical.startswith("mcp__") or canonical in _BUILTIN_EMAIL_TOOLS:
        return None
    if canonical not in _executable_tool_names():
        # Unknown builtin tool — fail closed. (MCP/email handled above.) The
        # allowlist is the full dispatchable set, not just schema-listed tools,
        # so legitimate schemaless tools (generate_image, vault_*, …) pass.
        return f"Unknown tool '{tool_type}'. It is not one of the available tools."

    if canonical in _FREEFORM_CONTENT_TOOLS:
        # Content is a raw freeform payload (code/command/prose), not a JSON args
        # object — never arg-validate it, even if it happens to be brace-delimited.
        return None

    stripped = content.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        try:
            parsed = json.loads(stripped)
        except (ValueError, TypeError):
            return f"Arguments for '{tool_type}' look like JSON but do not parse."
        if isinstance(parsed, dict):
            return validate_function_args(tool_type, parsed)
    return None
