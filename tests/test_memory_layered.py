"""Tests for the layered episodic/semantic memory provider (MR-5).

The vector store is mocked so tests run fully offline (no Chroma/fastembed).
"""

import asyncio
import time

from src.memory import MemoryManager
from src.memory_layered import (
    LayeredMemoryProvider,
    is_expired,
    score_memory,
)


class FakeVectorStore:
    """Offline stand-in for MemoryVectorStore."""

    healthy = True

    def __init__(self):
        self.added = []
        self.removed = []
        self.results = []

    def add(self, memory_id, text):
        self.added.append((memory_id, text))

    def remove(self, memory_id):
        self.removed.append(memory_id)

    def search(self, query, k=8):
        return self.results[:k]


def run(coro):
    return asyncio.run(coro)


# --- (c) multiplicative scoring ---------------------------------------------


def test_scoring_ranks_twice_confirmed_fact_over_stale_contradiction():
    now = time.time()
    confirmed = {
        "text": "Alice works at Acme",
        "category": "fact",
        "timestamp": now - 3600,   # recent
        "uses": 2,                 # twice reinforced
    }
    stale = {
        "text": "Alice works at Globex",
        "category": "fact",
        "timestamp": now - 60 * 86400,  # two months stale
        "uses": 0,                       # never confirmed
    }
    # Equal on-topic relevance isolates recency*importance as the decider.
    confirmed_score = score_memory(confirmed, relevance=0.8, now=now)
    stale_score = score_memory(stale, relevance=0.8, now=now)

    assert confirmed_score > stale_score
    # Sanity: reinforcement alone flips a same-age tie.
    a = {"category": "fact", "timestamp": now, "uses": 2}
    b = {"category": "fact", "timestamp": now, "uses": 0}
    assert score_memory(a, 0.5, now) > score_memory(b, 0.5, now)


def test_recall_ranks_confirmed_above_stale(tmp_path):
    manager = MemoryManager(str(tmp_path))
    vector = FakeVectorStore()
    provider = LayeredMemoryProvider(manager, vector)

    fresh = run(provider.remember("Alice works at Acme", owner="u", category="fact"))
    stale = run(provider.remember("Bob works at Globex", owner="u", category="fact"))

    # Age the second row and confirm the first twice via the shared uses counter.
    rows = manager.load_all()
    for r in rows:
        if r["id"] == stale.id:
            r["timestamp"] = int(time.time()) - 60 * 86400
    manager.save(rows)
    manager.increment_uses([fresh.id, fresh.id])

    vector.results = [
        {"memory_id": fresh.id, "score": 0.8},
        {"memory_id": stale.id, "score": 0.8},
    ]
    hits = run(provider.recall("where does someone work", owner="u", top_k=5))
    assert hits[0].memory.id == fresh.id
    assert hits[0].score >= (hits[1].score if len(hits) > 1 else 0.0)


# --- (e) per-type TTL --------------------------------------------------------


def test_ttl_expiry_drops_transient_fact(tmp_path):
    manager = MemoryManager(str(tmp_path))
    vector = FakeVectorStore()
    provider = LayeredMemoryProvider(manager, vector)

    durable = run(provider.remember("User's name is Alice", owner="u", category="fact"))
    transient = run(provider.remember("User is at the airport", owner="u", category="transient"))

    # Push the transient row past its 1h TTL.
    rows = manager.load_all()
    for r in rows:
        if r["id"] == transient.id:
            r["timestamp"] = int(time.time()) - 7200
    manager.save(rows)

    listed = run(provider.list_memories(owner="u"))
    ids = {m.id for m in listed}
    assert durable.id in ids
    assert transient.id not in ids

    vector.results = [
        {"memory_id": durable.id, "score": 0.9},
        {"memory_id": transient.id, "score": 0.9},
    ]
    hits = run(provider.recall("where is the user", owner="u", top_k=5))
    assert transient.id not in {h.memory.id for h in hits}


def test_is_expired_respects_none_ttl():
    now = time.time()
    assert is_expired({"category": "transient", "timestamp": now - 7200}, now) is True
    assert is_expired({"category": "fact", "timestamp": now - 10 * 86400}, now) is False


# --- (b) invalidate-do-not-delete -------------------------------------------


def test_invalidate_supersedes_without_deleting(tmp_path):
    manager = MemoryManager(str(tmp_path))
    vector = FakeVectorStore()
    provider = LayeredMemoryProvider(manager, vector)

    old = run(provider.remember("Alice lives in Paris", owner="u", category="fact"))
    new = run(provider.remember("Alice lives in Berlin", owner="u", category="fact"))

    ok = run(provider.invalidate(old.id, owner="u", superseded_by=new.id))
    assert ok is True

    # Row is NOT deleted from the JSON store.
    raw = {r["id"]: r for r in manager.load_all()}
    assert old.id in raw
    assert raw[old.id]["invalidated"] is True
    assert raw[old.id]["superseded_by"] == new.id
    assert old.id in vector.removed  # dropped from vector so it stops surfacing

    # Superseded memory is excluded from list + recall; the new one wins.
    ids = {m.id for m in run(provider.list_memories(owner="u"))}
    assert old.id not in ids
    assert new.id in ids

    vector.results = [
        {"memory_id": old.id, "score": 0.99},
        {"memory_id": new.id, "score": 0.5},
    ]
    hits = run(provider.recall("where does Alice live", owner="u", top_k=5))
    assert old.id not in {h.memory.id for h in hits}


# --- (a)/(d) extract-then-decide + reinforce-on-confirmation -----------------


def test_confirmation_reinforces_instead_of_duplicating(tmp_path):
    manager = MemoryManager(str(tmp_path))
    vector = FakeVectorStore()
    provider = LayeredMemoryProvider(manager, vector)

    first = run(provider.remember("Alice loves green tea", owner="u", category="preference"))
    again = run(provider.remember("Alice loves green tea", owner="u", category="preference"))

    assert again.id == first.id                 # no duplicate row created
    assert len(manager.load_all()) == 1
    assert manager.load_all()[0]["uses"] == 1   # confirmation bumped the counter
    assert len(vector.added) == 1               # vector not re-indexed


def test_reflect_purges_expired_and_superseded(tmp_path):
    manager = MemoryManager(str(tmp_path))
    vector = FakeVectorStore()
    provider = LayeredMemoryProvider(manager, vector)

    keep = run(provider.remember("User's name is Alice", owner="u", category="fact"))
    transient = run(provider.remember("User is at the gym", owner="u", category="transient"))
    superseded = run(provider.remember("Old address here", owner="u", category="fact"))
    run(provider.invalidate(superseded.id, owner="u"))

    rows = manager.load_all()
    for r in rows:
        if r["id"] == transient.id:
            r["timestamp"] = int(time.time()) - 7200
    manager.save(rows)

    summary = run(provider.reflect(owner="u"))
    assert summary["expired"] == 1
    assert summary["superseded"] == 1

    remaining = {r["id"] for r in manager.load_all()}
    assert remaining == {keep.id}
