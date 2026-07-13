"""Context taint tracking — the EchoLeak / prompt-injection-to-action defense.

When a session ingests untrusted external content (web pages, browser DOM), that
context becomes *tainted*. Any later credentialed real-world action in that
session — send email, write API call, browser action — must then go through
human approval, even if auto-confirm is off, so a poisoned page cannot make the
agent act with the user's authority.

This is the pragmatic "tier-split" v1: instead of fully separate web vs
credentialed agents, one agent whose authority to *act* is revoked once it has
*read* something untrusted, until a human approves.

State is per-session and in-process (resets on app restart) — fine for this
defense, which only needs to hold within a conversation.
"""
from __future__ import annotations

from typing import Optional

_TAINTED_SESSIONS: set[str] = set()

# Tools whose output is attacker-controllable external content.
#
# The summarize_* tools pull remote-feed / document content (RSS item titles and
# feed names from Miniflux, document titles/content from Paperless) — all of it
# controllable by whoever operates the feed or authors an ingested document, the
# same threat class as web_fetch. They ingest that text straight into model
# context, so they are taint SOURCES regardless of the fact that they never
# mutate state (mutation is the wrong axis for this set).
_UNTRUSTED_SOURCE_TOOLS = {
    "web_fetch",
    "web_search",
    "summarize_miniflux_unread",
    "summarize_paperless_recent",
}
_UNTRUSTED_PREFIXES = ("browser_", "playwright_")

# Real-world credentialed mutators that must not auto-fire in a tainted context.
_CREDENTIALED_MUTATORS = {"send_email", "reply_to_email", "bulk_email"}
_METHOD_AWARE = {"api_call", "app_api"}


def mark_tainted(session_id: Optional[str]) -> None:
    if session_id:
        _TAINTED_SESSIONS.add(session_id)


def is_tainted(session_id: Optional[str]) -> bool:
    return bool(session_id) and session_id in _TAINTED_SESSIONS


def clear(session_id: Optional[str]) -> None:
    _TAINTED_SESSIONS.discard(session_id or "")


def is_untrusted_source(tool_type: Optional[str]) -> bool:
    if not tool_type:
        return False
    return tool_type in _UNTRUSTED_SOURCE_TOOLS or tool_type.startswith(_UNTRUSTED_PREFIXES)


def is_credentialed_mutator(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    if not tool_type:
        return False
    if tool_type in _CREDENTIALED_MUTATORS:
        return True
    if tool_type.startswith(_UNTRUSTED_PREFIXES):  # browser actions can submit/exfil
        return True
    if tool_type in _METHOD_AWARE:
        try:
            from src.pending_actions import _is_write_api_call
            return _is_write_api_call(content)
        except Exception:
            return True  # unknown method → treat as write (safe)
    return False


def requires_taint_approval(session_id: Optional[str], tool_type: Optional[str],
                            content: Optional[str] = None) -> bool:
    """A credentialed action in a tainted session must be human-approved."""
    return is_tainted(session_id) and is_credentialed_mutator(tool_type, content)
