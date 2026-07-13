"""
mcp_allowlist.py

Curated allowlist for auto-wired MCP servers (MR-13: curated MCP aggregation).

Registry hygiene: the built-in auto-wire path (src/builtin_mcp.py) and the
generic connect path (src/mcp_manager.McpManager.connect_server) consult this
module before registering any server. The policy is FAIL-CLOSED:

  * A server that appears here and is NOT archived may be auto-wired.
  * A server marked ``archived`` is a curated "do not use" tripwire -- it is
    refused for EVERY path, including admin, so a deprecated/untrusted bundled
    server can never be silently re-wired. Un-archiving requires a code change.
  * A server absent from the registry is refused on the auto-wire path, but an
    explicit admin action (``admin_approved=True``) may still register it -- the
    operator owns the box and may add their own third-party servers.

This never widens what can run: it only ever refuses. It complements, and does
not replace, the approval queue (src/pending_actions.py) and taint model
(src/context_taint.py).
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class AllowlistEntry:
    """Provenance record for a curated MCP server.

    Attributes:
        server_id: Stable id the server registers under (matches the
            ``server_id`` passed to McpManager.connect_server).
        name: Human-readable display name.
        category: Coarse grouping ("builtin", "search", "home", ...).
        trust: Provenance/trust tier -- "first-party" (shipped in this repo) or
            "curated-third-party" (vetted external package).
        provenance: Short human note on where the server comes from / why it is
            trusted (or, for archived entries, why it must not be wired).
        archived: When True the server is a hard-refuse tripwire (see module
            docstring); never auto-wire and never admin-override.
    """

    server_id: str
    name: str
    category: str
    trust: str
    provenance: str
    archived: bool = False


# The curated allowlist. Keys are server ids. First-party "core-four" Python
# built-ins plus the vetted browser, SearXNG, and Home Assistant servers. The
# two archived entries are the legacy subprocess wrappers that were folded into
# native in-process execution (see src/builtin_mcp.py header) -- kept here so an
# accidental re-introduction of those ids is refused rather than auto-wired.
CURATED_ALLOWLIST: Dict[str, AllowlistEntry] = {
    # --- core-four: first-party Python stdio built-ins ---
    "image_gen": AllowlistEntry(
        server_id="image_gen",
        name="Built-in: Image Generation",
        category="builtin",
        trust="first-party",
        provenance="mcp_servers/image_gen_server.py (this repo)",
    ),
    "memory": AllowlistEntry(
        server_id="memory",
        name="Built-in: Memory",
        category="builtin",
        trust="first-party",
        provenance="mcp_servers/memory_server.py (this repo)",
    ),
    "rag": AllowlistEntry(
        server_id="rag",
        name="Built-in: RAG",
        category="builtin",
        trust="first-party",
        provenance="mcp_servers/rag_server.py (this repo)",
    ),
    "email": AllowlistEntry(
        server_id="email",
        name="Built-in: Email",
        category="builtin",
        trust="first-party",
        provenance="mcp_servers/email_server.py (this repo)",
    ),
    # --- vetted third-party / additional first-party built-ins ---
    "builtin_browser": AllowlistEntry(
        server_id="builtin_browser",
        name="Built-in: Browser",
        category="browser",
        trust="curated-third-party",
        provenance="npm @playwright/mcp (pinned, cache-gated launch)",
    ),
    "searxng": AllowlistEntry(
        server_id="searxng",
        name="Built-in: SearXNG",
        category="search",
        trust="curated-third-party",
        provenance="self-hosted SearXNG meta-search MCP (read-only search)",
    ),
    "home_assistant": AllowlistEntry(
        server_id="home_assistant",
        name="Built-in: Home Assistant",
        category="home",
        trust="curated-third-party",
        provenance="self-hosted Home Assistant MCP (mutations gated by approval queue)",
    ),
    # --- archived tripwires: folded into native execution, never wire as MCP ---
    "filesystem": AllowlistEntry(
        server_id="filesystem",
        name="Legacy: Filesystem (archived)",
        category="builtin",
        trust="first-party",
        provenance="folded into native tool_execution._direct_fallback; do not re-wire",
        archived=True,
    ),
    "web_search": AllowlistEntry(
        server_id="web_search",
        name="Legacy: Web Search (archived)",
        category="search",
        trust="first-party",
        provenance="folded into native tool_execution._direct_fallback; do not re-wire",
        archived=True,
    ),
}


def get_entry(
    server_id: str,
    registry: Optional[Dict[str, AllowlistEntry]] = None,
) -> Optional[AllowlistEntry]:
    """Return the curated entry for ``server_id``, or None if absent."""
    reg = CURATED_ALLOWLIST if registry is None else registry
    return reg.get(server_id)


def is_archived(
    server_id: str,
    registry: Optional[Dict[str, AllowlistEntry]] = None,
) -> bool:
    """Return True when ``server_id`` is a curated, archived (hard-refuse) entry."""
    entry = get_entry(server_id, registry)
    return bool(entry and entry.archived)


def is_allowlisted(
    server_id: str,
    registry: Optional[Dict[str, AllowlistEntry]] = None,
) -> bool:
    """Return True when ``server_id`` may be auto-wired (present, not archived)."""
    entry = get_entry(server_id, registry)
    return bool(entry and not entry.archived)


def check_registration(
    server_id: str,
    admin_approved: bool = False,
    registry: Optional[Dict[str, AllowlistEntry]] = None,
) -> Tuple[bool, str]:
    """Decide whether ``server_id`` may register. Fail-closed.

    Args:
        server_id: The id the server would register under.
        admin_approved: True only for an explicit operator/admin action (e.g. a
            server added through the admin routes). Never set this from the
            auto-wire path or from agent-driven registration of untrusted input.
        registry: Override the curated registry (used by tests).

    Returns:
        ``(allowed, reason)`` -- ``reason`` is a short, log-safe explanation.

    Policy:
        * archived entry  -> refused ALWAYS (even admin_approved).
        * present + live   -> allowed.
        * absent           -> allowed only when ``admin_approved`` is True.
    """
    if not isinstance(server_id, str) or not server_id.strip():
        return False, "refused: empty/invalid MCP server id"

    entry = get_entry(server_id, registry)
    if entry is not None and entry.archived:
        return False, (
            f"refused: MCP server '{server_id}' is archived and must never be "
            f"wired ({entry.provenance})"
        )
    if entry is not None:
        return True, f"allowlisted ({entry.trust}: {entry.provenance})"
    if admin_approved:
        return True, "admin-approved (not on curated MCP allowlist)"
    return False, (
        f"refused: MCP server '{server_id}' is not on the curated allowlist "
        f"and was not admin-approved"
    )
