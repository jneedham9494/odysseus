# routes/capture_routes.py
"""Share-sheet capture endpoint (MR-23 PWA + iOS Shortcuts).

A single owner-authenticated entry point, ``POST /api/capture``, that accepts
content shared from the OS share sheet (Android Web Share Target) or an iOS
Shortcut and files it as a Note via the existing notes/memory store.

Security posture (this is a network entry point, so it is treated as one):

* **Disabled by default.** The route only does anything when the operator has
  explicitly turned it on (``pwa_capture_enabled`` setting or the
  ``PWA_CAPTURE_ENABLED`` env var). Off => the path 404s and reveals nothing —
  "no token configured = off".
* **Owner-only.** A caller must present either a logged-in cookie session or a
  bearer API token that belongs to a real owner (and, when the token is scoped,
  carries a write scope). Anonymous callers get 401. The bearer token's owner is
  stamped on the note, so a paired Shortcut writes into the SAME notes the
  owner's browser sees — never an orphaned "api" silo.
* **Untrusted provenance.** Shared text/URLs are attacker-influenced external
  content. The captured note is tagged ``source="capture"`` so any later agent
  ingestion can treat it as untrusted (the existing taint model keys off
  provenance). Capture itself performs only a benign local write — it triggers
  no credentialed real-world action — so it does not enqueue a pending action;
  the human owner is directly and explicitly authoring the note.
"""

from __future__ import annotations

import logging
import os
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from core.database import Note, SessionLocal
from src.auth_helpers import require_user

logger = logging.getLogger(__name__)

# Bounds — validate everything at the boundary (untrusted input).
_MAX_TITLE = 500
_MAX_URL = 2048
_MAX_TEXT = 100_000
_MAX_FILES = 10
_MAX_FILE_BYTES = 1_000_000  # per file, read cap
_MAX_CONTENT = 200_000        # assembled note body cap

# When a scoped token is used it must carry one of these to write a capture.
# An unscoped/empty-scope token is owner-proof enough on its own.
_CAPTURE_SCOPES = {"todos:write", "memory:write"}


def _capture_enabled() -> bool:
    """True only when the operator has explicitly enabled share capture.

    Off by default so the endpoint is invisible until deliberately turned on.
    """
    env = os.getenv("PWA_CAPTURE_ENABLED", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    try:
        from src.settings import get_setting
        return bool(get_setting("pwa_capture_enabled", False))
    except Exception:  # settings unavailable — fail closed
        return False


def _require_capture_owner(request: Request) -> str:
    """Resolve the owning user or raise 401/403.

    Bearer API tokens (the iOS Shortcut path) authenticate as their owner and
    must carry a write scope when scoped. Cookie sessions go through
    ``require_user`` (401 when auth is configured; "" in single-user modes).
    """
    if getattr(request.state, "api_token", False):
        owner = getattr(request.state, "api_token_owner", None)
        if not owner:
            raise HTTPException(401, "API token is not bound to an owner")
        scopes = set(getattr(request.state, "api_token_scopes", []) or [])
        if scopes and not (scopes & _CAPTURE_SCOPES):
            raise HTTPException(403, "API token lacks a capture write scope")
        return owner
    return require_user(request)


def _clip(value: object, limit: int) -> str:
    """Coerce to a stripped string and clamp to ``limit`` characters."""
    if value is None:
        return ""
    text = str(value).strip()
    return text[:limit]


def _safe_url(raw: object) -> str:
    """Return an http(s) URL or "" — never echo an unvalidated scheme."""
    url = _clip(raw, _MAX_URL)
    if not url:
        return ""
    lowered = url.lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        return url
    return ""


async def _read_files(form) -> list[str]:
    """Extract text from shared upload files; label binaries by name only.

    Files are folded into the note body (we do not persist attachments here).
    Each file is read up to ``_MAX_FILE_BYTES``; undecodable bytes are recorded
    as a labelled placeholder rather than dropped silently.
    """
    chunks: list[str] = []
    count = 0
    for value in form.values():
        # Starlette UploadFile duck-typing: has .read and .filename.
        if not (hasattr(value, "read") and hasattr(value, "filename")):
            continue
        count += 1
        if count > _MAX_FILES:
            break
        name = _clip(getattr(value, "filename", "") or "file", 200)
        try:
            raw = await value.read(_MAX_FILE_BYTES + 1)
        except Exception as exc:  # never let a bad upload abort the capture
            logger.warning("capture: failed reading uploaded file %r: %s", name, exc)
            chunks.append(f"[unreadable file: {name}]")
            continue
        if len(raw) > _MAX_FILE_BYTES:
            raw = raw[:_MAX_FILE_BYTES]
        try:
            decoded = raw.decode("utf-8")
            chunks.append(f"### {name}\n{decoded}")
        except UnicodeDecodeError:
            chunks.append(f"[binary file: {name} ({len(raw)} bytes)]")
    return chunks


async def _parse_payload(request: Request) -> tuple[str, str, str, list[str]]:
    """Return (title, text, url, file_chunks) from JSON or form bodies.

    Web Share Target posts multipart/form-data; iOS Shortcuts commonly post
    JSON. Both are accepted; anything else is treated as an empty capture.
    """
    content_type = (request.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}
        return (
            _clip(data.get("title"), _MAX_TITLE),
            _clip(data.get("text"), _MAX_TEXT),
            _safe_url(data.get("url")),
            [],
        )
    if "multipart/form-data" in content_type or "x-www-form-urlencoded" in content_type:
        form = await request.form()
        files = await _read_files(form) if "multipart/form-data" in content_type else []
        return (
            _clip(form.get("title"), _MAX_TITLE),
            _clip(form.get("text"), _MAX_TEXT),
            _safe_url(form.get("url")),
            files,
        )
    return "", "", "", []


def _build_note_body(text: str, url: str, files: list[str]) -> str:
    """Assemble the note content, most-useful-first, clamped to a hard cap."""
    parts: list[str] = []
    if url:
        parts.append(url)
    if text:
        parts.append(text)
    parts.extend(files)
    return "\n\n".join(p for p in parts if p)[:_MAX_CONTENT]


def _derive_title(title: str, text: str, url: str) -> str:
    """Pick a human title: explicit, else first line of text, else the URL."""
    if title:
        return title
    if text:
        return text.splitlines()[0][:_MAX_TITLE].strip() or "Shared capture"
    if url:
        return url[:_MAX_TITLE]
    return "Shared capture"


def setup_capture_routes() -> APIRouter:
    """Build the ``/api/capture`` router. Mount unconditionally; the handler
    self-gates on ``_capture_enabled`` so the feature ships disabled."""
    router = APIRouter(prefix="/api", tags=["capture"])

    @router.post("/capture")
    async def capture(request: Request):
        # Gate first: a disabled feature is invisible (404), not merely 401.
        if not _capture_enabled():
            raise HTTPException(404, "Not found")

        owner = _require_capture_owner(request)  # 401/403 for bad callers

        title, text, url, files = await _parse_payload(request)
        body = _build_note_body(text, url, files)
        if not (title or body):
            raise HTTPException(422, "Nothing to capture: provide title, text, url, or a file")

        note = Note(
            id=str(uuid.uuid4()),
            owner=owner or None,
            title=_derive_title(title, text, url),
            content=body,
            note_type="note",
            # Provenance marker: externally-shared, untrusted content. Downstream
            # agent ingestion keys off this to apply the taint model.
            source="capture",
            label="capture",
        )
        db = SessionLocal()
        try:
            db.add(note)
            db.commit()
            db.refresh(note)
            note_id = note.id
        finally:
            db.close()

        logger.info("capture: filed note %s for owner=%r", note_id, owner or "<single-user>")

        # Browser share-sheet navigations expect an HTML landing; Shortcuts /
        # JSON callers want the id back.
        accept = (request.headers.get("accept") or "").lower()
        if "text/html" in accept and "application/json" not in accept:
            return RedirectResponse(url=f"/notes?captured={note_id}", status_code=303)
        return JSONResponse(status_code=201, content={"ok": True, "id": note_id})

    return router
