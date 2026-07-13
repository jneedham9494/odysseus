"""Unit tests for the cross-encoder rerank stage (src/reranker.py) and its
wiring into VectorRAG.search.

The cross-encoder is mocked throughout — a fake ``TextCrossEncoder`` whose
``rerank`` returns caller-supplied scores — so these tests never download a
model and run offline in CI. Coverage:

  * reranker reorders a candidate pool by cross-encoder relevance,
  * fallback-on-error preserves the caller's existing (bi-encoder) ordering,
  * the toggle off leaves ordering unchanged and never loads a model,
  * VectorRAG.search applies the rerank between candidate-gather and dedupe.
"""
import importlib

import pytest

import src.reranker as reranker


class _FakeEncoder:
    """Stand-in for fastembed TextCrossEncoder.

    ``scores_by_doc`` maps a document string to its cross-encoder score. Any
    unmapped document scores 0.0. Set ``raise_on_rerank`` to simulate a scoring
    failure, or ``bad_length`` to return a mismatched number of scores.
    """

    def __init__(self, scores_by_doc, raise_on_rerank=False, bad_length=False):
        self._scores = scores_by_doc
        self._raise = raise_on_rerank
        self._bad_length = bad_length
        self.calls = 0

    def rerank(self, query, documents):
        self.calls += 1
        if self._raise:
            raise RuntimeError("boom")
        scores = [self._scores.get(d, 0.0) for d in documents]
        if self._bad_length:
            return scores[:-1]  # drop one → length mismatch
        return scores


@pytest.fixture(autouse=True)
def _reset_reranker_state(monkeypatch):
    """Isolate each test: default the toggle on and clear cached encoder/latch."""
    monkeypatch.setenv("RAG_RERANK_ENABLED", "true")
    monkeypatch.delenv("RAG_RERANK_POOL", raising=False)
    reranker.reset_reranker_state()
    yield
    reranker.reset_reranker_state()


def _candidates():
    # Ordered as a bi-encoder would return them: c1 first, c3 last.
    return [
        {"id": "c1", "document": "alpha", "similarity": 0.9},
        {"id": "c2", "document": "bravo", "similarity": 0.8},
        {"id": "c3", "document": "charlie", "similarity": 0.7},
    ]


def _install_encoder(monkeypatch, encoder):
    monkeypatch.setattr(reranker, "get_reranker", lambda: encoder)
    return encoder


# --------------------------------------------------------------------------
# rerank_candidates
# --------------------------------------------------------------------------

def test_rerank_reorders_candidates_by_cross_encoder_score(monkeypatch):
    # charlie (last from the bi-encoder) is most relevant per the cross-encoder.
    encoder = _install_encoder(
        monkeypatch, _FakeEncoder({"charlie": 5.0, "alpha": 1.0, "bravo": 0.2})
    )
    out = reranker.rerank_candidates("q", _candidates())

    assert [c["id"] for c in out] == ["c3", "c1", "c2"]
    assert out[0]["rerank_score"] == 5.0
    assert encoder.calls == 1


def test_rerank_top_k_truncates_after_reordering(monkeypatch):
    _install_encoder(monkeypatch, _FakeEncoder({"charlie": 5.0, "alpha": 1.0, "bravo": 0.2}))
    out = reranker.rerank_candidates("q", _candidates(), top_k=2)

    assert [c["id"] for c in out] == ["c3", "c1"]


def test_rerank_disabled_returns_input_order_and_skips_model(monkeypatch):
    monkeypatch.setenv("RAG_RERANK_ENABLED", "false")
    # If the toggle is honored, get_reranker must never be consulted.
    encoder = _FakeEncoder({"charlie": 5.0})

    def _boom():
        raise AssertionError("get_reranker must not be called when disabled")

    monkeypatch.setattr(reranker, "get_reranker", _boom)
    out = reranker.rerank_candidates("q", _candidates())

    assert [c["id"] for c in out] == ["c1", "c2", "c3"]
    assert encoder.calls == 0


def test_rerank_falls_back_when_model_unavailable(monkeypatch):
    monkeypatch.setattr(reranker, "get_reranker", lambda: None)
    out = reranker.rerank_candidates("q", _candidates())

    assert [c["id"] for c in out] == ["c1", "c2", "c3"]
    assert all("rerank_score" not in c for c in out)


def test_rerank_scoring_error_preserves_bi_encoder_order(monkeypatch):
    _install_encoder(monkeypatch, _FakeEncoder({}, raise_on_rerank=True))
    out = reranker.rerank_candidates("q", _candidates())

    assert [c["id"] for c in out] == ["c1", "c2", "c3"]
    assert all("rerank_score" not in c for c in out)


def test_rerank_length_mismatch_preserves_order(monkeypatch):
    _install_encoder(monkeypatch, _FakeEncoder({"alpha": 1.0}, bad_length=True))
    out = reranker.rerank_candidates("q", _candidates())

    assert [c["id"] for c in out] == ["c1", "c2", "c3"]


def test_rerank_empty_and_invalid_query_are_noops(monkeypatch):
    _install_encoder(monkeypatch, _FakeEncoder({"charlie": 5.0}))
    assert reranker.rerank_candidates("", _candidates())[0]["id"] == "c1"
    assert reranker.rerank_candidates(None, _candidates())[0]["id"] == "c1"  # type: ignore[arg-type]
    assert reranker.rerank_candidates("q", []) == []


def test_rerank_pool_bounds_scored_candidates(monkeypatch):
    monkeypatch.setenv("RAG_RERANK_POOL", "1")
    # Only the first candidate is scored; the rest keep their original order and
    # trail the scored pool.
    encoder = _install_encoder(
        monkeypatch, _FakeEncoder({"alpha": 5.0, "charlie": 9.0})
    )
    out = reranker.rerank_candidates("q", _candidates())

    assert out[0]["id"] == "c1"
    assert [c["id"] for c in out] == ["c1", "c2", "c3"]
    # charlie would have won had it been in the pool — proof the pool was bounded.
    assert "rerank_score" not in out[2]


def test_rerank_enabled_toggle_parsing(monkeypatch):
    for value, expected in [("true", True), ("1", True), ("on", True),
                            ("false", False), ("0", False), ("no", False), ("", False)]:
        monkeypatch.setenv("RAG_RERANK_ENABLED", value)
        assert reranker.rerank_enabled() is expected
    monkeypatch.delenv("RAG_RERANK_ENABLED", raising=False)
    assert reranker.rerank_enabled() is True  # default on


# --------------------------------------------------------------------------
# get_reranker: lazy load + down-latch (mock fastembed import)
# --------------------------------------------------------------------------

def test_get_reranker_missing_fastembed_latches_down(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name.startswith("fastembed"):
            raise ImportError("no fastembed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    reranker.reset_reranker_state()

    assert reranker.get_reranker() is None
    # Latched: restore imports; still None without a reset (no re-probe).
    monkeypatch.setattr(builtins, "__import__", real_import)
    assert reranker.get_reranker() is None
    assert reranker._reranker_down is True


# --------------------------------------------------------------------------
# VectorRAG.search integration
# --------------------------------------------------------------------------

class _FakeLane:
    def __init__(self, name, rows):
        self.name = name
        self._rows = rows  # list of (id, distance, doc, meta)

    def count(self):
        return len(self._rows)

    def encode(self, texts):
        return [[0.0]]

    @property
    def collection(self):
        return self

    def query(self, query_embeddings, n_results, where, include):
        rows = self._rows[:n_results]
        return {
            "ids": [[r[0] for r in rows]],
            "distances": [[r[1] for r in rows]],
            "documents": [[r[2] for r in rows]],
            "metadatas": [[r[3] for r in rows]],
        }


def _rag_with_lane(rows):
    from src.rag_vector import VectorRAG

    rag = VectorRAG.__new__(VectorRAG)
    lane = _FakeLane("fastembed", rows)
    rag._lanes = [lane]
    rag._collection = lane
    rag._healthy = True
    return rag


def test_vectorrag_search_applies_rerank_before_dedupe(monkeypatch):
    import src.rag_vector as rag_vector

    # Bi-encoder order by distance: d_low < d_high → id "near" ranks first.
    rows = [
        ("near", 0.1, "alpha near", {"owner": None}),
        ("far", 0.4, "charlie far", {"owner": None}),
    ]
    rag = _rag_with_lane(rows)

    # Query "zzz" keyword-matches neither doc, so the hybrid score is pure
    # vector similarity → "near" (smaller distance) leads. The cross-encoder
    # then flips it: "charlie far" is most relevant.
    encoder = _FakeEncoder({"charlie far": 9.0, "alpha near": 1.0})
    monkeypatch.setattr(rag_vector, "rerank_candidates", reranker.rerank_candidates)
    monkeypatch.setattr(reranker, "get_reranker", lambda: encoder)
    monkeypatch.setenv("RAG_RERANK_ENABLED", "true")
    reranker.reset_reranker_state()

    out = rag.search("zzz", k=2)

    assert [r["id"] for r in out] == ["far", "near"]
    assert out[0]["rerank_score"] == 9.0
    assert encoder.calls == 1


def test_vectorrag_search_toggle_off_keeps_hybrid_order(monkeypatch):
    import src.rag_vector as rag_vector

    rows = [
        ("near", 0.1, "alpha near", {"owner": None}),
        ("far", 0.4, "charlie far", {"owner": None}),
    ]
    rag = _rag_with_lane(rows)
    monkeypatch.setattr(rag_vector, "rerank_candidates", reranker.rerank_candidates)
    monkeypatch.setenv("RAG_RERANK_ENABLED", "false")

    out = rag.search("zzz", k=2)

    # Unchanged hybrid order (pure vector for the non-matching query "zzz",
    # so "near" leads); no rerank_score attached.
    assert [r["id"] for r in out] == ["near", "far"]
    assert all("rerank_score" not in r for r in out)
