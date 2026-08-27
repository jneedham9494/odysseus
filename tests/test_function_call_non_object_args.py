import sys
from unittest.mock import MagicMock

from tests.helpers.import_state import clear_fake_modules

# This module needs the real agent-tool stack; importing it pulls in heavy
# DB/auth deps, so we stub those just long enough to import, then restore them.
# The agent-stack modules are only evicted when a previous test left a *stub*
# behind. Popping a real one and re-importing it rebinds the `src` package's
# attribute, so a later `import src.agent_tools as at` resolves to a different
# module object than the one whose functions everything else already holds -
# which silently breaks tests that monkeypatch it, and made the outcome depend
# on collection order (issue #41). src.tool_execution was already excluded here
# for exactly that reason; the same applies to its three siblings.
_ABSENT = object()
_AGENT_MODULES = ["src.agent_tools", "src.tool_parsing", "src.tool_schemas"]
_STUBBED = [
    "sqlalchemy", "sqlalchemy.orm", "sqlalchemy.ext", "sqlalchemy.ext.declarative",
    "sqlalchemy.ext.hybrid", "sqlalchemy.sql", "sqlalchemy.sql.expression",
    "src.database", "core.models", "core.database", "core.auth",
]
_saved_stubs = {name: sys.modules.get(name, _ABSENT) for name in _STUBBED}

clear_fake_modules(*_AGENT_MODULES)
for _mod in _STUBBED:
    if _mod not in sys.modules:
        sys.modules[_mod] = MagicMock()

import pytest  # noqa: E402
import src.agent_tools  # noqa: E402,F401
from src.tool_schemas import function_call_to_tool_block  # noqa: E402

# Drop the stubs we installed so they do not leak into later tests.
for _name, _original in _saved_stubs.items():
    if _original is _ABSENT:
        sys.modules.pop(_name, None)
    else:
        sys.modules[_name] = _original


@pytest.mark.parametrize("arguments", [
    '["ls -la"]',   # JSON array
    '"ls -la"',     # bare JSON string
    '42',            # JSON number
    'true',          # JSON bool
    'null',          # JSON null
])
def test_non_object_arguments_do_not_crash(arguments):
    """A native function call whose arguments are valid JSON but not an object
    must not raise (it used to throw AttributeError: 'list' object has no
    attribute 'get', aborting the entire agent stream)."""
    block = function_call_to_tool_block("bash", arguments)
    # Coerced to empty args -> empty bash command, but importantly NO crash.
    assert block is not None
    assert block.tool_type == "bash"
    assert block.content == ""


@pytest.mark.parametrize("tool_name", ["list_emails", "mcp__email__list_emails"])
def test_email_mcp_non_object_arguments_are_rejected(tool_name):
    block = function_call_to_tool_block(tool_name, '["INBOX"]')

    assert block is None


def test_edit_document_skips_non_object_edit_items():
    block = function_call_to_tool_block(
        "edit_document",
        '{"edits": ["bad", 42, null, {"find": "old", "replace": "new"}]}',
    )

    assert block is not None
    assert block.tool_type == "edit_document"
    assert block.content == "<<<FIND>>>\nold\n<<<REPLACE>>>\nnew\n<<<END>>>"


def test_suggest_document_skips_non_object_suggestion_items():
    block = function_call_to_tool_block(
        "suggest_document",
        '{"suggestions": ["bad", 42, null, {"find": "old", "replace": "new", "reason": "clearer"}]}',
    )

    assert block is not None
    assert block.tool_type == "suggest_document"
    assert block.content == (
        "<<<FIND>>>\nold\n<<<SUGGEST>>>\nnew\n<<<REASON>>>\nclearer\n<<<END>>>"
    )
