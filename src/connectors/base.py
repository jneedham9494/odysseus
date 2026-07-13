"""Connector ABC and value types.

A *connector* pulls records from an external source (RSS, forge, etc.) and
hands them to the single RAG write-path in ``ingest.py``. Two orthogonal axes
are made explicit on every record: **taint** (provenance is attacker
controllable — always true for connectors) and **sensitivity** (how sensitive
the content is — public/personal/sensitive). RSS, for example, is
``taint=untrusted`` yet ``sensitivity=public``.

This module performs NO I/O and imports nothing heavy so it stays trivially
testable.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from src.context_taint import SENSITIVITY_PUBLIC


@dataclass(frozen=True)
class ConnectorRecord:
    """One unit of source content to index.

    external_id: STABLE id from the source (e.g. a Miniflux entry id). Used for
        cursor advance and audit — NOT the dedupe key (dedupe is content-hash
        based, owner-scoped, inside add_documents_batch).
    text: content to index, already de-HTML'd by the connector.
    updated_at: ISO8601 or opaque; used to compute the new watermark cursor.
    sensitivity: per-record override of the connector's default_sensitivity.
    extra_metadata: UNTRUSTED — merged first and cannot override security keys
        (see ingest.ingest_records).
    """

    external_id: str
    text: str
    title: str = ""
    url: str = ""
    updated_at: str = ""
    sensitivity: Optional[str] = None
    extra_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class IngestResult:
    """Outcome of an ingest pass."""

    success: bool
    added: int = 0            # net-new chunks written
    seen: int = 0             # records processed
    new_cursor: Optional[str] = None
    message: str = ""


class Connector(ABC):
    """Base class for all connectors.

    Subclasses set the class attributes and implement ``fetch_changes``.
    """

    name: str                 # registry key + watermark key, e.g. "miniflux"
    source_type: str          # stamped into metadata, e.g. "connector:miniflux"
    default_sensitivity: str = SENSITIVITY_PUBLIC

    @abstractmethod
    async def fetch_changes(self, since: Optional[str]) -> list[ConnectorRecord]:
        """Return records with a cursor strictly greater than ``since``.

        ``since=None`` triggers the initial backfill window. Implementations
        MUST NOT execute or interpret fetched content — only normalize it to
        text. Records MUST be returned newest-last so the caller can take the
        last record's cursor as the new high-water mark.
        """
        raise NotImplementedError
