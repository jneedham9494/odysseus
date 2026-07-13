"""Layered episodic + semantic memory provider (MR-5 memory-layer v1).

Extends the native baseline without unifying backends (JSON store + Chroma
index reused as-is):
  (a) extract-then-decide writes: classify layer, dedupe, persist only new facts.
  (b) invalidate-do-not-delete: changing facts are superseded, never dropped.
  (c) recency * importance * relevance multiplicative recall scoring.
  (d) reinforce-on-confirmation: restating a fact bumps the shared `uses` counter.
  (e) per-type TTL: transient facts expire; durable facts do not.
  (f) reflection: a lightweight purge pass hookable to memory_added/consolidate.

Pure scoring/classification lives in src/memory_scoring.py and is re-exported
here for convenience.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

from src.memory import get_text_similarity
from src.memory_provider import MemoryProvider, MemoryRecord, MemorySearchHit
from src.memory_scoring import (  # noqa: F401  (re-exported for callers/tests)
    DEDUPE_SIMILARITY,
    DEFAULT_IMPORTANCE,
    IMPORTANCE_BY_CATEGORY,
    classify_layer,
    importance_factor,
    is_expired,
    is_invalidated,
    recency_factor,
    score_memory,
    ttl_for,
)

logger = logging.getLogger(__name__)

_CORE_FIELDS = {"id", "text", "timestamp", "source", "category", "owner", "session_id"}


class LayeredMemoryProvider(MemoryProvider):
    """Episodic/semantic memory layered over the native JSON + vector backends."""

    provider_id = "layered"
    display_name = "Layered episodic/semantic memory"

    def __init__(self, memory_manager, memory_vector=None, *, enabled: bool = True):
        self.memory_manager = memory_manager
        self.memory_vector = memory_vector
        self.enabled = enabled

    def _vector_available(self) -> bool:
        return bool(self.memory_vector and getattr(self.memory_vector, "healthy", True))

    @staticmethod
    def _to_record(entry: Dict[str, Any]) -> MemoryRecord:
        metadata = {k: v for k, v in entry.items() if k not in _CORE_FIELDS}
        return MemoryRecord(
            id=entry.get("id", ""),
            text=entry.get("text", ""),
            timestamp=entry.get("timestamp", 0),
            category=entry.get("category", "fact"),
            source=entry.get("source", "unknown"),
            owner=entry.get("owner"),
            session_id=entry.get("session_id"),
            metadata=metadata,
        )

    def _find_confirmation(
        self, text: str, candidates: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """Return an existing live memory that this write merely restates."""
        best: Optional[Dict[str, Any]] = None
        best_sim = DEDUPE_SIMILARITY
        for entry in candidates:
            if is_invalidated(entry) or is_expired(entry):
                continue
            sim = get_text_similarity(text, entry.get("text", ""))
            if sim >= best_sim:
                best_sim = sim
                best = entry
        return best

    async def remember(
        self,
        text: str,
        *,
        owner: Optional[str] = None,
        session_id: Optional[str] = None,
        category: str = "fact",
        source: str = "user",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryRecord:
        """(a) Extract-then-decide write. Near-duplicates reinforce, not duplicate."""
        text = (text or "").strip()
        if not text:
            raise ValueError("Memory text cannot be empty")

        memories = self.memory_manager.load_all()
        owned = [m for m in memories if owner is None or m.get("owner") == owner]

        # DECIDE: a near-duplicate is a confirmation, not a new fact.
        existing = self._find_confirmation(text, owned)
        if existing is not None:
            self.memory_manager.increment_uses([existing["id"]])
            existing["uses"] = int(existing.get("uses", 0) or 0) + 1
            return self._to_record(existing)

        # EXTRACT: classify layer + seed importance before persisting.
        entry = self.memory_manager.add_entry(text, source=source, category=category, owner=owner)
        entry["layer"] = classify_layer(category, source)
        entry["importance"] = IMPORTANCE_BY_CATEGORY.get(category, DEFAULT_IMPORTANCE)
        entry["invalidated"] = False
        if session_id:
            entry["session_id"] = session_id
        if metadata:
            entry["metadata"] = dict(metadata)
            override = metadata.get("importance")
            if isinstance(override, (int, float)):
                entry["importance"] = float(override)

        memories.append(entry)
        self.memory_manager.save(memories)
        if self._vector_available():
            self.memory_vector.add(entry["id"], entry["text"])
        return self._to_record(entry)

    async def recall(
        self, query: str, *, owner: Optional[str] = None, top_k: int = 5
    ) -> List[MemorySearchHit]:
        """(c) Rank live memories by recency * importance * relevance."""
        now = time.time()
        memories = self.memory_manager.load(owner=owner)
        live = [m for m in memories if not is_invalidated(m) and not is_expired(m, now)]
        if not live:
            return []

        relevance = self._relevance_map(query, live, top_k=top_k)
        scored: List[MemorySearchHit] = []
        for entry in live:
            rel = relevance.get(entry.get("id"), 0.0)
            if rel <= 0.0:
                continue
            scored.append(
                MemorySearchHit(
                    memory=self._to_record(entry),
                    provider_id=self.provider_id,
                    score=round(score_memory(entry, rel, now), 6),
                )
            )
        scored.sort(key=lambda hit: hit.score or 0.0, reverse=True)
        return scored[:top_k]

    def _relevance_map(
        self, query: str, live: List[Dict[str, Any]], *, top_k: int
    ) -> Dict[str, float]:
        """Return {memory_id: relevance in [0,1]} from vectors, keyword fallback."""
        relevance: Dict[str, float] = {}
        if self._vector_available():
            for result in self.memory_vector.search(query, k=max(top_k * 4, top_k)):
                if isinstance(result, dict) and result.get("memory_id"):
                    relevance[result["memory_id"]] = max(0.0, float(result.get("score") or 0.0))
        for entry in live:  # keyword fallback for rows the vector store missed
            mid = entry.get("id")
            if mid not in relevance:
                relevance[mid] = get_text_similarity(query, entry.get("text", ""))
        return relevance

    async def list_memories(
        self, *, owner: Optional[str] = None, limit: int = 100
    ) -> List[MemoryRecord]:
        now = time.time()
        rows = [
            m
            for m in self.memory_manager.load(owner=owner)
            if not is_invalidated(m) and not is_expired(m, now)
        ]
        return [self._to_record(m) for m in rows[:limit]]

    async def delete(self, memory_id: str, *, owner: Optional[str] = None) -> bool:
        memories = self.memory_manager.load_all()
        remaining = []
        deleted = False
        for entry in memories:
            if entry.get("id") == memory_id and (owner is None or entry.get("owner") == owner):
                deleted = True
                continue
            remaining.append(entry)
        if not deleted:
            return False
        self.memory_manager.save(remaining)
        if self._vector_available():
            self.memory_vector.remove(memory_id)
        return True

    async def invalidate(
        self,
        memory_id: str,
        *,
        owner: Optional[str] = None,
        superseded_by: Optional[str] = None,
    ) -> bool:
        """(b) Mark a memory superseded without deleting it (keeps audit trail)."""
        memories = self.memory_manager.load_all()
        found = False
        for entry in memories:
            if entry.get("id") == memory_id and (owner is None or entry.get("owner") == owner):
                entry["invalidated"] = True
                entry["invalidated_at"] = int(time.time())
                if superseded_by:
                    entry["superseded_by"] = superseded_by
                found = True
                break
        if not found:
            return False
        self.memory_manager.save(memories)
        # Drop from vector index so it stops surfacing; keep the JSON row.
        if self._vector_available():
            self.memory_vector.remove(memory_id)
        return True

    async def reflect(self, *, owner: Optional[str] = None) -> Dict[str, int]:
        """(f) Purge expired + superseded rows. Hookable to consolidate_memory."""
        now = time.time()
        memories = self.memory_manager.load_all()
        kept: List[Dict[str, Any]] = []
        expired = superseded = 0
        for entry in memories:
            scoped = owner is None or entry.get("owner") == owner
            if scoped and is_expired(entry, now):
                expired += 1
            elif scoped and is_invalidated(entry):
                superseded += 1
            else:
                kept.append(entry)
                continue
            if self._vector_available():
                self.memory_vector.remove(entry.get("id"))
        if expired or superseded:
            self.memory_manager.save(kept)
        return {"expired": expired, "superseded": superseded, "kept": len(kept)}

    def get_tool_schemas(self) -> List[Dict[str, Any]]:
        """Unique tool names so this never collides with the native provider."""
        return [
            {
                "name": "layered_memory_invalidate",
                "description": "Supersede a memory by id without deleting it.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "memory_id": {"type": "string"},
                        "superseded_by": {"type": "string"},
                    },
                    "required": ["memory_id"],
                },
            },
            {
                "name": "layered_memory_reflect",
                "description": "Purge expired/superseded memories for the owner.",
                "parameters": {"type": "object", "properties": {}},
            },
        ]

    async def handle_tool_call(self, name: str, arguments: Dict[str, Any]) -> Any:
        owner = arguments.get("owner")
        if name == "layered_memory_invalidate":
            ok = await self.invalidate(
                arguments["memory_id"], owner=owner, superseded_by=arguments.get("superseded_by")
            )
            return {"invalidated": ok}
        if name == "layered_memory_reflect":
            return await self.reflect(owner=owner)
        raise KeyError(f"Provider {self.provider_id} does not expose tool {name}")
