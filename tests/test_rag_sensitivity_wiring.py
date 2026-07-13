"""Wiring test: the live RAG write-path runs the graded sensitivity classifier.

Guards the blocking defect this MR fixes — that ``classify_and_redact`` was dead
code imported nowhere on the real write-path. These tests drive
``VectorRAG.add_document`` / ``add_documents_batch`` against a fake embedding lane
and assert the planted secret is masked before it reaches the collection AND the
fail-closed graded label is persisted as metadata.
"""
from __future__ import annotations

from src.rag_vector import VectorRAG

API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123"
SSN = "123-45-6789"


class _FakeCollection:
    def __init__(self) -> None:
        self.added: list[dict] = []

    def get(self, ids=None, **kwargs):
        return {"ids": []}

    def add(self, ids, embeddings, documents, metadatas):
        self.added.append({"ids": ids, "documents": documents, "metadatas": metadatas})


class _FakeLane:
    def __init__(self) -> None:
        self.name = "fastembed"
        self.collection = _FakeCollection()

    def encode(self, texts):
        return [[0.0] for _ in texts]


def _rag_with_fake_lane():
    rag = object.__new__(VectorRAG)
    lane = _FakeLane()
    rag._healthy = True
    rag._lanes = [lane]
    return rag, lane


def test_add_document_redacts_and_persists_sensitivity_label():
    rag, lane = _rag_with_fake_lane()
    assert rag.add_document(f"my key {API_KEY}", {"owner": "jack"}) is True
    stored = lane.collection.added[0]
    assert API_KEY not in stored["documents"][0]
    assert "[REDACTED:" in stored["documents"][0]
    assert stored["metadatas"][0]["sensitivity"] == "sensitive"


def test_add_document_mislabelled_public_is_upgraded_and_masked():
    rag, lane = _rag_with_fake_lane()
    rag.add_document(f"nothing here {SSN}", {"owner": "jack", "sensitivity": "public"})
    stored = lane.collection.added[0]
    assert SSN not in stored["documents"][0]
    assert stored["metadatas"][0]["sensitivity"] == "tier1-financial-health-id"


def test_add_document_respects_redact_opt_out():
    rag, lane = _rag_with_fake_lane()
    rag.add_document(f"my key {API_KEY}", {"owner": "jack", "redact": False})
    stored = lane.collection.added[0]
    assert API_KEY in stored["documents"][0]  # opt-out preserves raw text
    assert "sensitivity" not in stored["metadatas"][0]  # no label on opt-out


def test_add_documents_batch_redacts_and_labels():
    rag, lane = _rag_with_fake_lane()
    res = rag.add_documents_batch([
        (f"key {API_KEY}", {"owner": "jack"}),
        (f"ssn {SSN}", {"owner": "jack", "sensitivity": "public"}),
    ])
    assert res["success"] is True
    added = lane.collection.added[0]
    joined = " ".join(added["documents"])
    assert API_KEY not in joined
    assert SSN not in joined
    labels = {m["sensitivity"] for m in added["metadatas"]}
    assert "sensitive" in labels
    assert "tier1-financial-health-id" in labels
