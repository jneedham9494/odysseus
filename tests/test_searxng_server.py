"""SearXNG MCP server: tool listing, parsed results, and taint registration.

Network is fully mocked (monkeypatched `_fetch_json`) so the test is offline.
"""
import asyncio

import pytest

pytest.importorskip("mcp")

import mcp_servers.searxng_server as ss
import src.context_taint as ct


_FAKE_SEARXNG_JSON = {
    "query": "carmack",
    "results": [
        {
            "title": "John Carmack",
            "url": "https://example.com/carmack",
            "content": "Programmer and co-founder of id Software.",
            "engine": "duckduckgo",
        },
        {
            "title": "Doom",
            "url": "https://example.com/doom",
            "content": "1993 first-person shooter.",
        },
    ],
}


def test_list_tools_exposes_web_search():
    tools = asyncio.run(ss.list_tools())
    names = [t.name for t in tools]
    assert names == ["web_search"]
    assert "query" in tools[0].inputSchema["required"]


def test_call_tool_returns_parsed_cited_results(monkeypatch):
    monkeypatch.setattr(ss, "_resolve_base_url", lambda: "http://searx.local")

    async def _fake_fetch(base_url, query, count):
        assert base_url == "http://searx.local"
        assert query == "carmack"
        return _FAKE_SEARXNG_JSON

    monkeypatch.setattr(ss, "_fetch_json", _fake_fetch)

    out = asyncio.run(ss.call_tool("web_search", {"query": "carmack"}))
    text = out[0].text
    assert "John Carmack" in text
    assert "https://example.com/carmack" in text
    assert "Doom" in text
    assert "untrusted external web content" in text


def test_call_tool_empty_query_errors():
    out = asyncio.run(ss.call_tool("web_search", {"query": "   "}))
    assert "needs a 'query'" in out[0].text


def test_call_tool_unconfigured_base_url(monkeypatch):
    monkeypatch.setattr(ss, "_resolve_base_url", lambda: "")
    out = asyncio.run(ss.call_tool("web_search", {"query": "x"}))
    assert "not configured" in out[0].text


def test_call_tool_no_results(monkeypatch):
    monkeypatch.setattr(ss, "_resolve_base_url", lambda: "http://searx.local")

    async def _empty(base_url, query, count):
        return {"results": []}

    monkeypatch.setattr(ss, "_fetch_json", _empty)
    out = asyncio.run(ss.call_tool("web_search", {"query": "nothing"}))
    assert "No results found" in out[0].text


def test_count_is_clamped():
    assert ss._clamp_count(99) == ss._MAX_RESULTS
    assert ss._clamp_count(0) == 1
    assert ss._clamp_count("bad") == ss._DEFAULT_RESULTS
    assert ss._clamp_count(3) == 3


def test_searxng_tool_registered_as_untrusted_source():
    # The qualified MCP tool name must taint the session (EchoLeak defense).
    assert ct.is_untrusted_source("mcp__searxng__web_search")
    # And it is a read, not a credentialed mutator.
    assert not ct.is_credentialed_mutator("mcp__searxng__web_search")
