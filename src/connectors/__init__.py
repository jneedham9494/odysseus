"""Connector framework: pull external source content into RAG as inert,
taint-stamped, redaction-enforced rows.

Public surface:
- ``Connector`` / ``ConnectorRecord`` / ``IngestResult`` — the ABC + value types.
- ``ingest_records`` / ``run_sync`` — the single write-path + sync orchestrator.
- ``WatermarkStore`` — per-(connector, owner) sync cursor.
- ``get_connector`` — registry lookup.
"""
from __future__ import annotations

from src.connectors.base import Connector, ConnectorRecord, IngestResult
from src.connectors.ingest import ingest_records, run_sync
from src.connectors.registry import available_connectors, get_connector
from src.connectors.state import WatermarkStore

__all__ = [
    "Connector",
    "ConnectorRecord",
    "IngestResult",
    "ingest_records",
    "run_sync",
    "WatermarkStore",
    "get_connector",
    "available_connectors",
]
