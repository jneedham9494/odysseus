"""Pure scoring + classification helpers for the layered memory provider (MR-5).

Kept backend-free and side-effect-free so recall ranking, TTL expiry, and layer
classification are unit-testable in isolation. Operate on plain memory dicts as
loaded from the JSON store (see src/memory.py).
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

DAY = 86400

# (e) Per-type time-to-live in seconds. None means the fact never expires.
TTL_BY_CATEGORY: Dict[str, Optional[int]] = {
    "transient": 3600,
    "event": 7 * DAY,
    "task": 30 * DAY,
    "identity": None,
    "preference": None,
    "contact": None,
    "fact": None,
}
DEFAULT_TTL: Optional[int] = None

# Recency decay half-life per type (seconds).
DEFAULT_HALF_LIFE = 30 * DAY
HALF_LIFE_BY_CATEGORY: Dict[str, int] = {
    "transient": 1800,
    "event": 3 * DAY,
    "task": 7 * DAY,
}

# Base importance per type before reinforcement.
IMPORTANCE_BY_CATEGORY: Dict[str, float] = {
    "identity": 1.0,
    "preference": 0.8,
    "contact": 0.8,
    "fact": 0.6,
    "task": 0.5,
    "event": 0.4,
    "transient": 0.2,
}
DEFAULT_IMPORTANCE = 0.5

# (d) Each confirmation (use) adds this fraction of base importance.
REINFORCE_WEIGHT = 0.5

# Categories/sources that make a memory episodic rather than semantic.
EPISODIC_CATEGORIES = {"event", "task", "observation", "session", "transient"}
EPISODIC_SOURCES = {"chat", "session", "observation"}

# Above this text similarity a write is a confirmation, not a distinct fact.
DEDUPE_SIMILARITY = 0.85


def classify_layer(category: str, source: str) -> str:
    """Return "episodic" for time-bound observations, else "semantic"."""
    if category in EPISODIC_CATEGORIES or source in EPISODIC_SOURCES:
        return "episodic"
    return "semantic"


def ttl_for(category: str) -> Optional[int]:
    """TTL in seconds for a category, or None if it never expires."""
    return TTL_BY_CATEGORY.get(category, DEFAULT_TTL)


def is_expired(entry: Dict[str, Any], now: Optional[float] = None) -> bool:
    """True when a transient memory has outlived its per-type TTL."""
    ttl = ttl_for(entry.get("category", "fact"))
    if ttl is None:
        return False
    now = time.time() if now is None else now
    return (now - float(entry.get("timestamp", 0) or 0)) > ttl


def is_invalidated(entry: Dict[str, Any]) -> bool:
    """True when a memory has been superseded (invalidate-do-not-delete)."""
    return bool(entry.get("invalidated"))


def recency_factor(entry: Dict[str, Any], now: Optional[float] = None) -> float:
    """Exponential recency decay in (0, 1] based on the type's half-life."""
    now = time.time() if now is None else now
    age = max(0.0, now - float(entry.get("timestamp", 0) or 0))
    half_life = HALF_LIFE_BY_CATEGORY.get(entry.get("category", "fact"), DEFAULT_HALF_LIFE)
    return 0.5 ** (age / float(half_life))


def importance_factor(entry: Dict[str, Any]) -> float:
    """Base importance grown by confirmation count (the shared `uses` counter)."""
    base = entry.get("importance")
    if not isinstance(base, (int, float)):
        base = IMPORTANCE_BY_CATEGORY.get(entry.get("category", "fact"), DEFAULT_IMPORTANCE)
    uses = int(entry.get("uses", 0) or 0)
    return float(base) * (1.0 + REINFORCE_WEIGHT * uses)


def score_memory(entry: Dict[str, Any], relevance: float, now: Optional[float] = None) -> float:
    """(c) Multiplicative recall score: recency * importance * relevance.

    A twice-confirmed, on-topic fact outranks a stale, unconfirmed contradicting
    one at equal relevance, because recency and importance compound.
    """
    return recency_factor(entry, now) * importance_factor(entry) * max(0.0, float(relevance))
