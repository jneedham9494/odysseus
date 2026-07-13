"""rag_types.py — shared types for RAG retrieval that keep provenance metadata
attached to retrieved content.

SECURITY / TAINT SEAM
=====================
Any path that feeds retrieved content into model context MUST carry AND honor
the metadata attached to each chunk. In particular the provenance/sensitivity
keys stamped at ingestion time (present once connector/ingest branches land):

    - ``taint``        e.g. "untrusted" — content is attacker-controllable
    - ``source_type``  e.g. "connector:miniflux" — where the content came from
    - ``sensitivity``  e.g. "public" / "personal" / "sensitive"

Bare-string retrieval (returning ``list[str]``) DROPS this metadata, which is a
latent EchoLeak bypass: untrusted connector content can reach the model with no
provenance for a downstream taint hook to act on. Returning ``RetrievedChunk``
keeps ``text`` and ``metadata`` side by side so a future taint-application step
(see ``src/context_taint.py``) can inspect provenance without re-querying the
store.

This module only makes the metadata SURVIVE the retrieval path; it deliberately
does NOT apply taint (that hook lives elsewhere and is wired separately).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping

# Provenance/sensitivity keys that MUST NOT be stripped when retrieved content
# travels toward model context. Single source of truth for the taint seam.
PROVENANCE_KEYS: tuple[str, ...] = ("taint", "source_type", "sensitivity")


@dataclass(frozen=True)
class RetrievedChunk:
    """A retrieved chunk with its provenance metadata kept attached.

    Attributes:
        text: The raw chunk text (what a bare-string path used to return).
        metadata: The full metadata dict from the vector store, carried through
            UNMODIFIED so provenance keys (taint/source_type/sensitivity) and
            any other stamped keys survive to downstream consumers.
        score: Retrieval score (hybrid similarity); 0.0 when unknown.
    """

    text: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    score: float = 0.0

    @classmethod
    def from_search_result(cls, result: Mapping[str, Any]) -> "RetrievedChunk":
        """Build a chunk from a ``VectorRAG.search()`` result mapping.

        ``search()`` yields ``{"document", "metadata", "similarity", ...}``. The
        metadata dict is copied (so callers cannot mutate the store's cached
        view), but every key — including provenance keys — is preserved.

        Args:
            result: A single search-result mapping.

        Returns:
            A ``RetrievedChunk`` carrying the document text, a copy of its
            metadata, and its similarity score.

        Raises:
            TypeError: If ``result`` is not a mapping.
        """
        if not isinstance(result, Mapping):
            raise TypeError(
                f"search result must be a mapping, got {type(result).__name__}"
            )
        meta = result.get("metadata")
        meta_dict: Dict[str, Any] = dict(meta) if isinstance(meta, Mapping) else {}
        text = result.get("document") or ""
        raw_score = result.get("similarity", 0.0)
        try:
            score = float(raw_score)
        except (TypeError, ValueError):
            score = 0.0
        return cls(text=str(text), metadata=meta_dict, score=score)

    def provenance(self) -> Dict[str, Any]:
        """Return only the provenance keys present in metadata (taint-seam view).

        A convenience for a future taint hook: the subset of ``metadata`` limited
        to :data:`PROVENANCE_KEYS`. Absent keys are simply omitted.
        """
        return {k: self.metadata[k] for k in PROVENANCE_KEYS if k in self.metadata}
