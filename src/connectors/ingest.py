"""The single connector write-path into RAG.

``ingest_records`` stamps security-critical metadata, chunks each record (the
batch write-path does NOT chunk — only ``index_personal_documents`` did), and
hands ``(chunk, metadata)`` tuples to ``VectorRAG.add_documents_batch``, which
redacts → owner-scoped-id → dedupes → embeds → adds.

Security invariants enforced here:
- ``redact=True`` is ALWAYS stamped and never emitted as False for connector
  content, so secrets/PII in fetched content are masked before storage.
- Security keys (source_type, owner, sensitivity, taint, redact, ...) are
  stamped LAST, so a crafted ``extra_metadata`` (e.g. {"redact": False}) is
  overridden and cannot weaken the record.
- Chroma down (get_rag_manager() is None) fails closed: no write, no cursor
  advance, so the next sync safely retries (at-least-once, made safe by the
  content-hash idempotent dedupe).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Iterable

from src.connectors.base import ConnectorRecord, IngestResult
from src.context_taint import TAINT_UNTRUSTED, normalize_sensitivity
from src.rag_singleton import get_rag_manager

if TYPE_CHECKING:  # avoid import cycles / heavy imports at runtime
    from src.connectors.base import Connector
    from src.connectors.state import WatermarkStore


def _stamp(connector: "Connector", owner: str, record: ConnectorRecord) -> dict[str, Any]:
    """Build the metadata base for a record; security keys stamped last."""
    sensitivity = normalize_sensitivity(record.sensitivity or connector.default_sensitivity)
    base: dict[str, Any] = dict(record.extra_metadata or {})  # UNTRUSTED — merged first
    # --- security-critical keys stamped LAST; these WIN over extra_metadata ---
    base.update(
        {
            "source_type": connector.source_type,   # "connector:miniflux"
            "connector": connector.name,
            "owner": owner,                          # owner-scopes dedupe id + search
            "sensitivity": sensitivity,              # graded label
            "taint": TAINT_UNTRUSTED,                # provenance marker
            "redact": True,                          # ENFORCED — never False
            "external_id": str(record.external_id),
            "url": record.url or "",
            "title": record.title or "",
        }
    )
    assert base["redact"] is True  # invariant: connector content is always redacted
    return base


def ingest_records(
    connector: "Connector", owner: str, records: Iterable[ConnectorRecord]
) -> IngestResult:
    """Stamp, chunk, and write records through the redaction-enforced batch."""
    if not owner or not isinstance(owner, str):
        return IngestResult(success=False, message="owner is required")

    rag = get_rag_manager()
    if rag is None:  # Chroma down → fail closed, DO NOT advance watermark
        return IngestResult(success=False, message="RAG unavailable (503)")

    record_list = list(records)
    docs: list[tuple[str, dict[str, Any]]] = []
    seen = 0
    for record in record_list:
        if not record.text or not isinstance(record.text, str):
            continue
        seen += 1
        base = _stamp(connector, owner, record)
        # Chunk here — add_documents_batch does NOT chunk. Redaction runs
        # per-chunk inside the batch.
        for chunk_id, chunk in enumerate(rag._split_into_chunks(record.text)):
            meta = dict(base)
            meta["chunk_id"] = chunk_id
            docs.append((chunk, meta))

    if not docs:
        return IngestResult(success=True, added=0, seen=seen, message="no ingestable records")

    result = rag.add_documents_batch(docs)  # redact → id → dedupe → embed → add
    if not result.get("success"):
        return IngestResult(
            success=False, seen=seen, message=result.get("message", "batch failed")
        )

    new_cursor = _new_cursor(record_list)
    return IngestResult(
        success=True,
        added=result.get("added_count", 0),
        seen=seen,
        new_cursor=new_cursor,
        message="ok",
    )


def _new_cursor(records: list[ConnectorRecord]) -> str | None:
    """The new high-water mark is the last (newest) record's cursor."""
    if not records:
        return None
    last = records[-1]
    return last.updated_at or str(last.external_id)


async def run_sync(
    connector: "Connector", owner: str, store: "WatermarkStore"
) -> IngestResult:
    """Orchestrate the cursor lifecycle: watermark → fetch → ingest → advance.

    Delivered as a plain callable (usable from tests/CLI); registering it as a
    ScheduledTask is a later MR. The cursor advances ONLY on a successful
    ingest, giving at-least-once delivery made safe by idempotent dedupe.
    """
    since = store.get_cursor(connector.name, owner)
    records = await connector.fetch_changes(since)  # newest-last
    result = ingest_records(connector, owner, records)
    if result.success and result.new_cursor:
        store.advance(connector.name, owner, result.new_cursor)
    return result
