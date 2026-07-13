"""
tool_capping.py

Cap the number of tools surfaced to the model per request to a bounded,
relevance-ranked set (MR-14). Injecting every tool schema on every request
degrades tool selection and inflates latency/cost; a request never needs more
than a couple dozen tools, so keep the always-available tools plus the most
relevant RAG-ranked candidates and drop the long tail.

RAG ranking reuses the ChromaDB tool index (src/tool_index.py). The functions
here are pure and index-agnostic — the index (or a ranker callable) is passed
in — so they are testable without the embedding stack.

This is pre-prompt tool SELECTION, not admission: it shapes which schemas the
model sees, and runs before the request. Admission (accept/reject a call the
model actually made) lives in src/admission and is a separate concern.
"""

import logging
from typing import Callable, Iterable, List, Optional, Set

logger = logging.getLogger(__name__)

# Hard cap on tools surfaced to the model in a single request.
MAX_TOOLS_PER_REQUEST = 20


def rank_by_relevance(
    query: str,
    candidates: Iterable[str],
    tool_index: Optional[object] = None,
) -> List[str]:
    """Order *candidates* by descending RAG relevance to *query*.

    Uses the tool index's retrieval scores when available; candidates the index
    does not rank are appended in stable alphabetical order. With no query or no
    index, falls back to alphabetical order so the result is always deterministic.
    """
    cands = list(dict.fromkeys(candidates))  # de-dupe, preserve first-seen order
    if not query or tool_index is None:
        return sorted(cands)
    try:
        ranked = tool_index.retrieve(query, k=max(len(cands) * 2, 50))
    except Exception as exc:  # index unavailable/unhealthy — degrade gracefully
        logger.warning("tool ranking retrieval failed; using alphabetical: %s", exc)
        return sorted(cands)
    order = {name: idx for idx, name in enumerate(ranked)}
    # Ranked candidates first (by score), then the rest alphabetically.
    return sorted(cands, key=lambda t: (order.get(t, len(order)), t))


def cap_tools_for_request(
    query: str,
    tools: Iterable[str],
    *,
    always_include: Optional[Iterable[str]] = None,
    limit: int = MAX_TOOLS_PER_REQUEST,
    tool_index: Optional[object] = None,
    ranker: Optional[Callable[[str, List[str]], List[str]]] = None,
) -> Set[str]:
    """Return at most *limit* tools, keeping always-available + most relevant.

    Args:
        query: the user message used to rank relevance.
        tools: the candidate tool names selected for this request.
        always_include: tools that must be kept if present (float to the top).
        limit: maximum number of tools to return (defaults to the module cap).
        tool_index: RAG index used for relevance ranking (optional).
        ranker: override ranking function taking (query, candidates) -> ordered
            list; used mainly for testing. When given, *tool_index* is ignored.

    The always-include set is prioritised but still counts toward *limit*: if it
    alone exceeds the cap, the most relevant of those are kept.
    """
    tool_set: Set[str] = set(tools)
    if limit <= 0:
        return set()
    if len(tool_set) <= limit:
        return tool_set

    must = set(always_include or ()) & tool_set
    ordered_input = sorted(tool_set)
    if ranker is not None:
        ranked = ranker(query, ordered_input)
    else:
        ranked = rank_by_relevance(query, ordered_input, tool_index)

    # Guarantee every candidate is represented even if a custom ranker dropped
    # some, so the cap never silently loses a tool it should have considered.
    seen = set(ranked)
    ranked = list(ranked) + [t for t in ordered_input if t not in seen]

    # Must-keep tools first (in ranked order), then the remainder (in ranked
    # order); truncate to the limit.
    prioritised = [t for t in ranked if t in must] + [t for t in ranked if t not in must]
    return set(prioritised[:limit])
