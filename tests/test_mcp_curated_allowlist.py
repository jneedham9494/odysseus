"""Tests for MR-13 curated MCP allowlist + registration guard.

Covers:
  * the curated allowlist / provenance registry (src/mcp_allowlist.py),
  * the fail-closed guard in McpManager.connect_server,
  * the auto-wire guard's decision surface in src/builtin_mcp.py.
"""

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from src import mcp_allowlist as al
from src.mcp_allowlist import (
    AllowlistEntry,
    CURATED_ALLOWLIST,
    check_registration,
    is_allowlisted,
    is_archived,
)
from src.mcp_manager import McpManager


# --------------------------------------------------------------------------- #
# Registry / provenance
# --------------------------------------------------------------------------- #

def test_core_four_are_allowlisted():
    for sid in ("image_gen", "memory", "rag", "email"):
        assert is_allowlisted(sid), sid
        entry = CURATED_ALLOWLIST[sid]
        assert entry.trust == "first-party"
        assert entry.provenance  # provenance is recorded


def test_searxng_and_home_assistant_are_curated_allowlisted():
    for sid in ("searxng", "home_assistant"):
        assert is_allowlisted(sid), sid
        assert CURATED_ALLOWLIST[sid].trust == "curated-third-party"


def test_archived_entries_are_not_allowlisted():
    for sid in ("filesystem", "web_search"):
        assert is_archived(sid), sid
        assert not is_allowlisted(sid), sid


def test_check_registration_allows_allowlisted():
    ok, reason = check_registration("memory")
    assert ok is True
    assert "allowlisted" in reason


def test_check_registration_refuses_unknown_without_admin():
    ok, reason = check_registration("totally_unknown_server")
    assert ok is False
    assert "not on the curated allowlist" in reason


def test_check_registration_allows_unknown_with_admin_approval():
    ok, reason = check_registration("user_custom_server", admin_approved=True)
    assert ok is True
    assert "admin-approved" in reason


def test_check_registration_refuses_archived_even_with_admin():
    ok, reason = check_registration("filesystem", admin_approved=True)
    assert ok is False
    assert "archived" in reason


def test_check_registration_refuses_empty_id():
    ok, reason = check_registration("   ", admin_approved=True)
    assert ok is False
    assert "empty" in reason or "invalid" in reason


def test_check_registration_honors_injected_registry():
    custom = {
        "good": AllowlistEntry("good", "Good", "test", "first-party", "unit"),
        "gone": AllowlistEntry("gone", "Gone", "test", "first-party", "unit", archived=True),
    }
    assert check_registration("good", registry=custom)[0] is True
    assert check_registration("gone", registry=custom, admin_approved=True)[0] is False
    assert check_registration("memory", registry=custom)[0] is False  # real list ignored


# --------------------------------------------------------------------------- #
# McpManager.connect_server guard
# --------------------------------------------------------------------------- #

def test_connect_allowlisted_server_registers():
    mgr = McpManager()
    with patch.object(McpManager, "_connect_stdio", new=AsyncMock(return_value=True)) as stub:
        result = asyncio.run(
            mgr.connect_server("memory", "Built-in: Memory", "stdio", command="python", args=["m.py"])
        )
    assert result is True
    stub.assert_awaited_once()


def test_connect_non_allowlisted_server_refused_without_spawn():
    mgr = McpManager()
    with patch.object(McpManager, "_connect_stdio", new=AsyncMock(return_value=True)) as stub:
        result = asyncio.run(
            mgr.connect_server("evil_server", "Evil", "stdio", command="python", args=["e.py"])
        )
    assert result is False
    stub.assert_not_awaited()  # never spawned a subprocess
    assert mgr.get_server_status("evil_server")["status"] == "refused"


def test_connect_archived_server_refused_even_when_admin_approved():
    mgr = McpManager()
    with patch.object(McpManager, "_connect_stdio", new=AsyncMock(return_value=True)) as stub:
        result = asyncio.run(
            mgr.connect_server(
                "filesystem", "Legacy FS", "stdio",
                command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"],
                admin_approved=True,
            )
        )
    assert result is False
    stub.assert_not_awaited()
    assert mgr.get_server_status("filesystem")["status"] == "refused"


def test_connect_admin_approved_unknown_server_registers():
    mgr = McpManager()
    with patch.object(McpManager, "_connect_stdio", new=AsyncMock(return_value=True)) as stub:
        result = asyncio.run(
            mgr.connect_server(
                "user_added_1234", "My Server", "stdio",
                command="python", args=["s.py"], admin_approved=True,
            )
        )
    assert result is True
    stub.assert_awaited_once()


# --------------------------------------------------------------------------- #
# builtin_mcp auto-wire regression: existing built-ins are unaffected
# --------------------------------------------------------------------------- #

def test_all_shipped_builtins_are_allowlisted():
    from src.builtin_mcp import _BUILTIN_NPX_SERVERS, _BUILTIN_SERVERS

    for sid in _BUILTIN_SERVERS:
        assert is_allowlisted(sid), f"shipped built-in {sid} must be allowlisted"
    for sid in _BUILTIN_NPX_SERVERS:
        assert is_allowlisted(sid), f"shipped NPX built-in {sid} must be allowlisted"


def test_register_builtin_skips_archived_and_wires_allowlisted():
    """An archived id injected into the built-in table is never connected,
    while a legitimate allowlisted built-in still is."""
    import src.builtin_mcp as bm

    calls = []

    class FakeManager:
        async def connect_server(self, **kwargs):
            calls.append(kwargs["server_id"])
            return True

    injected = {
        "memory": ("mcp_servers/memory_server.py", "Built-in: Memory"),
        "filesystem": ("mcp_servers/filesystem_server.py", "Legacy FS"),
    }

    async def _run():
        with patch.object(bm, "_BUILTIN_SERVERS", injected), \
             patch.object(bm, "_BUILTIN_NPX_SERVERS", {}), \
             patch.object(bm.os.path, "exists", return_value=True), \
             patch.object(bm, "_find_npx", return_value="npx"):
            await bm.register_builtin_servers(FakeManager())
            # Let the scheduled per-server connect tasks run.
            await asyncio.sleep(0)
            await asyncio.sleep(0)

    asyncio.run(_run())
    assert "memory" in calls
    assert "filesystem" not in calls


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
