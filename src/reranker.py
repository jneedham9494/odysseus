"""
reranker.py

Cross-encoder rerank stage for retrieval (RAG hybrid search).

A bi-encoder (the embedding model) scores query and document *independently*,
so its ranking is only ever an approximation. A cross-encoder scores the
(query, document) pair *jointly*, which is far more accurate but too expensive
to run over a whole index — so it is used as a second stage: over-fetch a wide
candidate pool with the cheap bi-encoder, then re-order the pool with the
cross-encoder and keep the top-k.

Runs locally via fastembed's ``TextCrossEncoder`` (ONNX, CPU/GPU) — no new
service. Mirrors ``src/embeddings.py``: lazy load, a process-level "down" latch
so a missing/broken model is only probed once, and graceful fallback — if the
model can't load or scoring errors, the caller's existing ordering is returned
unchanged. Reranking must never break search.

Config (env):
  RAG_RERANK_ENABLED   "true"/"false"  — master toggle (default on, safe-off).
  RAG_RERANK_MODEL     model name       — default a small ms-marco MiniLM.
  RAG_RERANK_POOL      int              — max candidates scored per query.
"""

import os
import logging
from typing import Any, Dict, List, Optional

from src.constants import FASTEMBED_CACHE_DIR

logger = logging.getLogger(__name__)

_DEFAULT_RERANK_MODEL = "Xenova/ms-marco-MiniLM-L-6-v2"
# Cap the pool the cross-encoder scores per query. A cross-encoder is ~1-2 orders
# of magnitude slower than a bi-encoder, so bound the work even if a caller
# over-fetches a very wide pool. 30 comfortably covers k*6 for the usual k<=5.
_DEFAULT_RERANK_POOL = 30

# Sentinel so an unbounded score never accidentally passes an env check.
_TRUTHY = {"1", "true", "yes", "on"}

_reranker = None  # cached encoder instance (lazy)
_reranker_down = False  # process-level latch: don't re-probe a broken model


def rerank_enabled() -> bool:
    """Whether the rerank stage is on. Default on; any non-truthy value is off."""
    return os.getenv("RAG_RERANK_ENABLED", "true").strip().lower() in _TRUTHY


def _rerank_pool() -> int:
    """Max candidates scored per query (>=1); malformed env falls back to default."""
    raw = os.getenv("RAG_RERANK_POOL", "")
    if not raw:
        return _DEFAULT_RERANK_POOL
    try:
        value = int(raw)
    except (TypeError, ValueError):
        logger.warning("Invalid RAG_RERANK_POOL=%r; using %d", raw, _DEFAULT_RERANK_POOL)
        return _DEFAULT_RERANK_POOL
    return value if value >= 1 else _DEFAULT_RERANK_POOL


def reset_reranker_state() -> None:
    """Drop the cached encoder and clear the down-latch so the next call re-loads.

    Call after changing the rerank model/toggle at runtime — otherwise a latch
    tripped once (or a stale cached model) would persist for the whole process.
    """
    global _reranker, _reranker_down
    _reranker = None
    _reranker_down = False


def get_reranker():
    """Return a lazily-loaded cross-encoder, or ``None`` if unavailable.

    Loads fastembed's ``TextCrossEncoder`` once and caches it. If fastembed is
    missing or the model fails to load, latches "down" and returns ``None`` for
    the rest of the process so callers fall back to their existing ordering
    without paying the load cost again.
    """
    global _reranker, _reranker_down
    if _reranker is not None:
        return _reranker
    if _reranker_down:
        return None

    try:
        from fastembed.rerank.cross_encoder import TextCrossEncoder
    except ImportError as e:
        _reranker_down = True
        logger.warning(
            "fastembed TextCrossEncoder unavailable (%s); rerank disabled for this process", e
        )
        return None

    model = os.getenv("RAG_RERANK_MODEL", _DEFAULT_RERANK_MODEL)
    try:
        cache_dir = FASTEMBED_CACHE_DIR
        os.makedirs(cache_dir, exist_ok=True)
        _reranker = TextCrossEncoder(model_name=model, cache_dir=cache_dir)
        logger.info("Cross-encoder reranker loaded model=%s", model)
        return _reranker
    except Exception as e:
        _reranker_down = True
        logger.warning(
            "Cross-encoder reranker failed to load (model=%s): %s; using bi-encoder order", model, e
        )
        return None


def rerank_candidates(
    query: str,
    candidates: List[Dict[str, Any]],
    top_k: Optional[int] = None,
    document_key: str = "document",
    score_key: str = "rerank_score",
) -> List[Dict[str, Any]]:
    """Re-order ``candidates`` by cross-encoder relevance to ``query``.

    Each candidate dict must carry its text under ``document_key``. The
    cross-encoder score is written back under ``score_key`` on the returned
    dicts. On any problem — toggle off, model unavailable, bad input, scoring
    error — the input ordering is returned unchanged (never raises). Reranking
    is a best-effort refinement, so search degrades to the existing hybrid order
    rather than failing.

    Args:
        query: The search query. Non-empty ``str`` required; else a no-op.
        candidates: Bi-encoder candidate pool (already ordered by the caller).
        top_k: If set (>0), truncate the reranked result to this many rows.
        document_key: Key holding each candidate's text.
        score_key: Key under which to store the cross-encoder score.

    Returns:
        A list of candidate dicts, reranked when possible, else the input
        (optionally truncated to ``top_k``).
    """
    def _truncate(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if top_k is not None and top_k > 0:
            return rows[:top_k]
        return rows

    if not rerank_enabled():
        return _truncate(candidates)
    if not query or not isinstance(query, str):
        return _truncate(candidates)
    if not candidates or not isinstance(candidates, list):
        return _truncate(candidates)

    encoder = get_reranker()
    if encoder is None:
        return _truncate(candidates)

    pool = candidates[: _rerank_pool()]
    try:
        documents = [str(c.get(document_key, "")) for c in pool]
        scores = list(encoder.rerank(query, documents))
        if len(scores) != len(pool):
            logger.warning(
                "Reranker returned %d scores for %d docs; keeping bi-encoder order",
                len(scores),
                len(pool),
            )
            return _truncate(candidates)
    except Exception as e:
        logger.warning("Rerank scoring failed (%s); keeping bi-encoder order", e)
        return _truncate(candidates)

    for candidate, score in zip(pool, scores):
        candidate[score_key] = round(float(score), 4)

    # Stable sort by cross-encoder score (desc). Candidates beyond the scored
    # pool keep their original relative order and trail the scored rows.
    reranked = sorted(pool, key=lambda c: c.get(score_key, float("-inf")), reverse=True)
    reranked.extend(candidates[len(pool):])
    return _truncate(reranked)
