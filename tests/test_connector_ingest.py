"""ingest_records: stamping, redaction-enforced, security-key override, idempotency.

Uses a FakeRAG that mirrors the real add_documents_batch security-relevant
behaviour (redact-when-meta.redact, owner-scoped content-hash id + dedupe) so
tests run fully offline without ChromaDB / numpy embedding.
"""
import asyncio
import hashlib
import os

import src.connectors.ingest as ingest_mod
from src.connectors.base import Connector, ConnectorRecord
from src.context_taint import (
    SENSITIVITY_PUBLIC,
    SENSITIVITY_SENSITIVE,
    TAINT_UNTRUSTED,
    is_untrusted_source_type,
)


def _doc_id(text: str, owner: str) -> str:
    key = f"{owner}\x00{text}" if owner else text
    return f"doc_{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"


class FakeRAG:
    """Mirrors VectorRAG's chunking + redaction + owner-scoped dedupe."""

    def __init__(self):
        self.captured: list[tuple[str, dict]] = []
        self.seen_ids: set[str] = set()

    def _split_into_chunks(self, text, chunk_size=1000, overlap=200):
        if not text:
            return []
        if len(text) <= chunk_size:
            return [text]
        return [text[i:i + chunk_size] for i in range(0, len(text), chunk_size - overlap)]

    def add_documents_batch(self, docs):
        from src.rag_redaction import redact_for_index

        added = 0
        for text, meta in docs:
            stored = redact_for_index(text)[0] if meta.get("redact", True) else text
            doc_id = _doc_id(stored, meta.get("owner") or "")
            self.captured.append((stored, meta))
            if doc_id not in self.seen_ids:
                self.seen_ids.add(doc_id)
                added += 1
        return {"success": True, "added_count": added, "total_count": len(docs)}


class _FakeConnector(Connector):
    name = "miniflux"
    source_type = "connector:miniflux"
    default_sensitivity = SENSITIVITY_PUBLIC

    async def fetch_changes(self, since):  # unused here
        return []


def _use_fake(monkeypatch) -> FakeRAG:
    rag = FakeRAG()
    monkeypatch.setattr(ingest_mod, "get_rag_manager", lambda: rag)
    return rag


def test_every_chunk_is_stamped(monkeypatch):
    rag = _use_fake(monkeypatch)
    records = [ConnectorRecord(external_id="7", text="hello world", title="T", url="u")]
    result = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert result.success
    assert rag.captured
    for _text, meta in rag.captured:
        assert meta["taint"] == TAINT_UNTRUSTED
        assert meta["sensitivity"] in {"public", "personal", "sensitive"}
        assert meta["owner"] == "jack"
        assert meta["source_type"].startswith("connector:")
        assert is_untrusted_source_type(meta["source_type"])
        assert meta["redact"] is True
        assert meta["external_id"] == "7"
        assert "chunk_id" in meta


def test_extra_metadata_cannot_override_security_keys(monkeypatch):
    rag = _use_fake(monkeypatch)
    evil = {"redact": False, "taint": "trusted", "source_type": "connector:evil",
            "owner": "attacker", "harmless": "kept"}
    records = [ConnectorRecord(external_id="1", text="data", extra_metadata=evil)]
    ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    _text, meta = rag.captured[0]
    assert meta["redact"] is True                       # override wins
    assert meta["taint"] == TAINT_UNTRUSTED
    assert meta["source_type"] == "connector:miniflux"
    assert meta["owner"] == "jack"
    assert meta["harmless"] == "kept"                    # non-security key preserved


def test_per_record_sensitivity_override(monkeypatch):
    rag = _use_fake(monkeypatch)
    records = [ConnectorRecord(external_id="1", text="x", sensitivity=SENSITIVITY_SENSITIVE)]
    ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert rag.captured[0][1]["sensitivity"] == "sensitive"


def test_unknown_sensitivity_normalized_to_public(monkeypatch):
    rag = _use_fake(monkeypatch)
    records = [ConnectorRecord(external_id="1", text="x", sensitivity="bogus")]
    ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert rag.captured[0][1]["sensitivity"] == "public"


def test_planted_secret_is_masked_before_storage(monkeypatch):
    rag = _use_fake(monkeypatch)
    secret = "sk-abcdefghijklmnopqrstuvwxyz012345"
    records = [ConnectorRecord(external_id="1", text=f"leak {secret} here")]
    ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    stored, _meta = rag.captured[0]
    assert secret not in stored
    assert "[REDACTED:API_KEY]" in stored


def test_idempotent_reingest(monkeypatch):
    rag = _use_fake(monkeypatch)
    records = [ConnectorRecord(external_id="1", text="same content", updated_at="1")]
    first = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    second = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert first.added == 1
    assert second.added == 0  # content-hash dedupe → nothing net-new


def test_new_cursor_is_last_record_updated_at(monkeypatch):
    _use_fake(monkeypatch)
    records = [
        ConnectorRecord(external_id="1", text="a", updated_at="1"),
        ConnectorRecord(external_id="9", text="b", updated_at="9"),
    ]
    result = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert result.new_cursor == "9"
    assert result.seen == 2


def test_owner_required(monkeypatch):
    _use_fake(monkeypatch)
    result = ingest_mod.ingest_records(_FakeConnector(), "", [])
    assert result.success is False
    assert "owner" in result.message


def test_rag_unavailable_fails_closed(monkeypatch):
    monkeypatch.setattr(ingest_mod, "get_rag_manager", lambda: None)
    records = [ConnectorRecord(external_id="1", text="x")]
    result = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert result.success is False
    assert result.new_cursor is None  # no cursor advance when RAG is down


def test_empty_text_records_skipped(monkeypatch):
    rag = _use_fake(monkeypatch)
    records = [ConnectorRecord(external_id="1", text="")]
    result = ingest_mod.ingest_records(_FakeConnector(), "jack", records)
    assert result.success
    assert result.added == 0
    assert rag.captured == []


class _StubConnector(_FakeConnector):
    def __init__(self, records):
        self._records = records

    async def fetch_changes(self, since):
        self.last_since = since
        return list(self._records)


def _store(tmp_path):
    from src.connectors.state import WatermarkStore

    return WatermarkStore(db_path=os.path.join(str(tmp_path), "state.db"))


def test_run_sync_advances_cursor_on_success(monkeypatch, tmp_path):
    _use_fake(monkeypatch)
    store = _store(tmp_path)
    conn = _StubConnector([ConnectorRecord(external_id="5", text="x", updated_at="5")])
    result = asyncio.run(ingest_mod.run_sync(conn, "jack", store))
    assert result.success
    assert conn.last_since is None  # first sync → backfill
    assert store.get_cursor("miniflux", "jack") == "5"


def test_run_sync_does_not_advance_when_rag_down(monkeypatch, tmp_path):
    monkeypatch.setattr(ingest_mod, "get_rag_manager", lambda: None)
    store = _store(tmp_path)
    conn = _StubConnector([ConnectorRecord(external_id="5", text="x", updated_at="5")])
    result = asyncio.run(ingest_mod.run_sync(conn, "jack", store))
    assert result.success is False
    assert store.get_cursor("miniflux", "jack") is None  # cursor untouched


def test_run_sync_passes_existing_cursor(monkeypatch, tmp_path):
    _use_fake(monkeypatch)
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "3")
    conn = _StubConnector([ConnectorRecord(external_id="8", text="x", updated_at="8")])
    asyncio.run(ingest_mod.run_sync(conn, "jack", store))
    assert conn.last_since == "3"
    assert store.get_cursor("miniflux", "jack") == "8"
