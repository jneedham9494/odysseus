"""Authenticated connector ingest route — ``POST /api/connectors/ingest``.

External automation (the n8n personal-intelligence workflows) pushes batches of
records here so automation can finally feed cognition. Every record is funneled
through the SAME taint-stamped write-path as the Miniflux connector
(:func:`src.connectors.ingest.ingest_records`): redacted → stamped
``taint=untrusted`` + ``source_type=connector:n8n:<workflow>`` +
sensitivity-labelled. This route NEVER bypasses ``ingest_records`` and never
sets security metadata itself.

Security posture (fail-closed):
- Auth is a DEDICATED ingest credential, ``INGEST_TOKEN`` (Infisical/env),
  compared in constant time. It is deliberately NOT the internal-tool loopback
  token — n8n is a separate external caller. No token configured, a missing
  token, or a wrong token → 401.
- The path is auth-exempt at the middleware (see app.py) precisely because an
  external caller cannot present a session cookie; the credential is proven
  HERE instead. This mirrors the task-webhook pattern.
- Owner is resolved SERVER-SIDE from ``INGEST_OWNER`` and validated against the
  auth user map. A caller cannot write into an arbitrary owner's memory: a body
  ``owner`` that disagrees with the configured owner is rejected (403).
- The batch is capped (count + per-field size) to bound work and memory.

PORT NOTE (rebuild/n8n-ingest onto refactor/base):
    The connector framework (MR-2: ``src/connectors/base.py`` and
    ``src/connectors/ingest.py``) is a PREREQUISITE not yet present on
    ``refactor/base``. Its imports are guarded so this module mounts cleanly
    today. Auth (401) and server-side owner resolution (403) do NOT need the
    framework and are fully enforced now; the actual write-path is gated behind
    an availability check that fails closed with 503 until MR-2 is merged (at
    which point the guard becomes an inert no-op and full ingest is live).
"""
from __future__ import annotations

import hashlib
import os
import secrets
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, ValidationError

from core.auth import normalize_known_username
from src.connectors.n8n import N8nConnector, sanitize_workflow

try:  # MR-2 (connector framework) prerequisite — inert once merged.
    from src.connectors.base import ConnectorRecord
    from src.connectors.ingest import ingest_records
    _CONNECTOR_FRAMEWORK = True
except ImportError:  # pragma: no cover - exercised only on refactor/base
    ConnectorRecord = None  # type: ignore[assignment,misc]
    ingest_records = None  # type: ignore[assignment]
    _CONNECTOR_FRAMEWORK = False

# --- batch / field caps -------------------------------------------------
MAX_RECORDS = 100
MAX_BODY_LEN = 100_000
MAX_TITLE_LEN = 1_000
MAX_URL_LEN = 2_048
MAX_PUBLISHED_LEN = 64

_INGEST_TOKEN_ENV = "INGEST_TOKEN"
_INGEST_OWNER_ENV = "INGEST_OWNER"


class IngestRecordIn(BaseModel):
    """One record pushed by n8n. ``source_type``/``owner`` here are advisory —
    the write-path stamps the authoritative security keys and ignores these."""

    body: str = Field(min_length=1, max_length=MAX_BODY_LEN)
    title: str = Field(default="", max_length=MAX_TITLE_LEN)
    url: str = Field(default="", max_length=MAX_URL_LEN)
    published: str = Field(default="", max_length=MAX_PUBLISHED_LEN)
    sensitivity: Optional[str] = Field(default=None, max_length=32)
    # Accepted for schema compatibility with the n8n payload but NOT trusted:
    # the connector's source_type wins, and owner is resolved server-side.
    source_type: Optional[str] = Field(default=None, max_length=128)
    owner: Optional[str] = Field(default=None, max_length=128)


class IngestBatchIn(BaseModel):
    """A batch of records from a single n8n workflow."""

    workflow: Optional[str] = Field(default=None, max_length=64)
    owner: Optional[str] = Field(default=None, max_length=128)
    records: list[IngestRecordIn] = Field(min_length=1, max_length=MAX_RECORDS)


def _presented_token(request: Request) -> Optional[str]:
    """Extract the ingest token from Authorization: Bearer or X-Ingest-Token."""
    header = request.headers.get("X-Ingest-Token")
    if header:
        return header.strip()
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _require_ingest_token(request: Request) -> None:
    """Fail-closed dedicated-credential check. Raises 401 on any mismatch.

    Distinct from the internal-tool loopback token: it compares ONLY against
    ``INGEST_TOKEN``. An unset/empty configured token rejects everything so a
    misconfigured deploy can never accept unauthenticated writes.
    """
    configured = (os.environ.get(_INGEST_TOKEN_ENV) or "").strip()
    presented = _presented_token(request)
    if not configured or not presented:
        raise HTTPException(401, "ingest authentication required")
    if not secrets.compare_digest(configured, presented):
        raise HTTPException(401, "ingest authentication required")


def _resolve_owner(request: Request, body_owner: Optional[str]) -> str:
    """Resolve the ingest owner server-side and validate the caller's claim.

    The owner is the operator-configured ``INGEST_OWNER`` — never a value the
    caller can freely choose. If the caller *does* send an owner, it must match
    (case-insensitively) or the request is refused. When the auth manager is
    configured, the owner must be a known user so records land in a real silo.
    """
    configured = (os.environ.get(_INGEST_OWNER_ENV) or "").strip()
    if not configured:
        # No server-side owner → nowhere safe to write. Fail closed.
        raise HTTPException(503, "ingest owner not configured")

    auth_mgr = getattr(request.app.state, "auth_manager", None)
    resolved = configured.lower()
    if auth_mgr is not None and getattr(auth_mgr, "is_configured", False):
        known = normalize_known_username(auth_mgr.users, configured)
        if not known:
            raise HTTPException(503, "ingest owner is not a known user")
        resolved = known

    if body_owner is not None:
        claimed = str(body_owner).strip().lower()
        if claimed and claimed != resolved:
            raise HTTPException(403, "cannot ingest into another owner's memory")
    return resolved


def _to_record(item: IngestRecordIn):
    """Map validated input to a ConnectorRecord. Mirrors Miniflux: title is
    prepended to the body and an external_id is derived (url, else content
    hash) for audit — dedupe itself is content-hash based in the write-path."""
    title = item.title.strip()
    body = item.body.strip()
    text = f"{title}\n\n{body}".strip() if title else body
    external_id = item.url.strip() or f"sha256:{hashlib.sha256(body.encode('utf-8')).hexdigest()[:16]}"
    extra = {"published": item.published} if item.published else {}
    return ConnectorRecord(
        external_id=external_id,
        text=text,
        title=title,
        url=item.url.strip(),
        updated_at=item.published.strip(),
        sensitivity=item.sensitivity,
        extra_metadata=extra,
    )


def setup_connector_routes() -> APIRouter:
    router = APIRouter(prefix="/api/connectors", tags=["connectors"])

    @router.post("/ingest")
    async def ingest(request: Request):
        # 1) Dedicated-credential auth (fail-closed) BEFORE any body parsing.
        _require_ingest_token(request)

        # 2) Parse + validate the batch (caps enforced by the models).
        try:
            raw = await request.json()
        except Exception:
            raise HTTPException(400, "invalid JSON body")
        try:
            batch = IngestBatchIn.model_validate(raw)
        except ValidationError as e:
            raise HTTPException(422, f"invalid ingest batch: {e.error_count()} error(s)")

        # 3) Validate the workflow slug (it becomes part of source_type).
        workflow = sanitize_workflow(batch.workflow)
        if workflow is None:
            raise HTTPException(422, "invalid workflow slug")

        # 4) Resolve owner server-side; reject cross-owner writes.
        owner = _resolve_owner(request, batch.owner)

        # 5) Connector framework (MR-2) must be present to reach the write-path.
        #    Fail closed until it is merged onto this base; auth + owner checks
        #    above have already run, so this NEVER weakens the security posture.
        if not _CONNECTOR_FRAMEWORK:
            raise HTTPException(
                503,
                "connector framework (MR-2) prerequisite not available on this deployment",
            )

        # 6) Hand everything to the shared taint-stamped write-path. We build
        #    ONE connector for the workflow; per-record owner/source_type in the
        #    payload are ignored (ingest_records stamps the authoritative keys).
        connector = N8nConnector(workflow)
        records = [_to_record(item) for item in batch.records]
        result = ingest_records(connector, owner, records)

        if not result.success:
            # RAG down / owner missing → fail closed with a service error, not
            # a partial success. 503 so n8n retries (dedupe makes retry safe).
            raise HTTPException(503, result.message or "ingest failed")

        return {
            "ok": True,
            "source_type": connector.source_type,
            "owner": owner,
            "seen": result.seen,
            "added": result.added,
        }

    return router
