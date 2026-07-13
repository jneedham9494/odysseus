"""MR-23 PWA + iOS Shortcuts: manifest/service-worker serving + capture endpoint.

Two concerns:

1. ``/manifest.json`` and ``/sw.js`` are served with their canonical
   content-types (``application/manifest+json`` / ``text/javascript``) and the
   service worker carries ``Service-Worker-Allowed: /`` so it can claim root
   scope.
2. ``POST /api/capture`` is an owner-only entry point: it ships disabled
   (404 until enabled), then 401s anonymous callers and stores a note for an
   authenticated owner.

Transport note (same rationale as tests/test_notes_fail_closed_auth.py): drive
the ASGI app through ``httpx.ASGITransport`` rather than ``TestClient`` to avoid
the anyio portal-thread hang, and inject identity with a pure-ASGI shim that
writes the exact ``request.state`` fields the real auth middleware sets.
"""
import json
import uuid
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import core.database as cdb
from core.database import Note
import routes.capture_routes as cap
from routes.pwa_routes import setup_pwa_routes

_STATIC = Path(__file__).resolve().parent.parent / "static"
_PEER = ("203.0.113.7", 54321)


class _Identity:
    """Pure-ASGI identity shim mirroring the auth middleware.

    Headers drive the injected ``request.state``:
      x-test-user           -> cookie session for that username
      x-test-token-owner    -> bearer API token bound to that owner
      x-test-token-scopes   -> comma-separated scopes for the bearer token
    No identity headers => anonymous (the state an auth regression leaves).
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            state = scope.setdefault("state", {})
            user = headers.get(b"x-test-user")
            owner = headers.get(b"x-test-token-owner")
            if owner:
                state["current_user"] = "api"
                state["api_token"] = True
                state["api_token_owner"] = owner.decode()
                scopes = headers.get(b"x-test-token-scopes")
                state["api_token_scopes"] = (
                    [s for s in scopes.decode().split(",") if s] if scopes else []
                )
            elif user:
                state["current_user"] = user.decode()
        await self.app(scope, receive, send)


def _temp_db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'capture.db'}",
        connect_args={"check_same_thread": False},
        poolclass=NullPool,
    )
    cdb.Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _client(app):
    transport = httpx.ASGITransport(app=app, client=_PEER)
    return httpx.AsyncClient(transport=transport, base_url="http://capture.test")


# --------------------------------------------------------------------------- #
# manifest / service worker serving
# --------------------------------------------------------------------------- #

@pytest.fixture
def pwa_app():
    app = FastAPI()
    app.include_router(setup_pwa_routes(_STATIC))
    return _Identity(app)


async def test_manifest_served_with_manifest_content_type(pwa_app):
    async with _client(pwa_app) as c:
        r = await c.get("/manifest.json")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/manifest+json")
    body = json.loads(r.text)
    # Share target must point the OS share sheet at the capture endpoint.
    assert body["share_target"]["action"] == "/api/capture"
    assert body["share_target"]["method"] == "POST"


async def test_service_worker_served_with_js_content_type_and_root_scope(pwa_app):
    async with _client(pwa_app) as c:
        r = await c.get("/sw.js")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/javascript")
    # Must be allowed to control the whole origin, not just /static/.
    assert r.headers.get("service-worker-allowed") == "/"


# --------------------------------------------------------------------------- #
# capture endpoint
# --------------------------------------------------------------------------- #

@pytest.fixture
def cap_env(monkeypatch, tmp_path):
    """Capture router over a temp DB, feature ENABLED. Returns (app, factory)."""
    factory = _temp_db(tmp_path)
    monkeypatch.setattr(cap, "SessionLocal", factory)
    monkeypatch.setenv("PWA_CAPTURE_ENABLED", "true")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.delenv("LOCALHOST_BYPASS", raising=False)
    app = FastAPI()
    app.state.auth_manager = SimpleNamespace(is_configured=True)
    app.include_router(cap.setup_capture_routes())
    return _Identity(app), factory


async def test_capture_disabled_by_default_returns_404(monkeypatch, tmp_path):
    factory = _temp_db(tmp_path)
    monkeypatch.setattr(cap, "SessionLocal", factory)
    monkeypatch.delenv("PWA_CAPTURE_ENABLED", raising=False)
    # No settings file in the test env => get_setting("pwa_capture_enabled")
    # falls back to its False default, so the feature is off.
    app = FastAPI()
    app.state.auth_manager = SimpleNamespace(is_configured=True)
    app.include_router(cap.setup_capture_routes())
    shim = _Identity(app)
    async with _client(shim) as c:
        # Even a valid owner sees nothing while the feature is off.
        r = await c.post(
            "/api/capture",
            json={"text": "hi"},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "todos:write"},
        )
    assert r.status_code == 404


async def test_capture_unauthenticated_returns_401(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post("/api/capture", json={"text": "leak", "url": "https://x.test"})
    assert r.status_code == 401
    db = factory()
    try:
        assert db.query(Note).count() == 0
    finally:
        db.close()


async def test_capture_bearer_token_owner_stores_note(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            json={"title": "Read later", "text": "great article", "url": "https://ex.test/a"},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "todos:write"},
        )
    assert r.status_code == 201
    note_id = r.json()["id"]
    db = factory()
    try:
        note = db.query(Note).filter(Note.id == note_id).one()
        assert note.owner == "alice"
        assert note.title == "Read later"
        assert note.source == "capture"          # untrusted provenance marker
        assert "https://ex.test/a" in note.content
    finally:
        db.close()


async def test_capture_cookie_session_stores_note(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            json={"text": "from the browser share sheet"},
            headers={"x-test-user": "bob"},
        )
    assert r.status_code == 201
    db = factory()
    try:
        note = db.query(Note).filter(Note.owner == "bob").one()
        assert "browser share sheet" in note.content
    finally:
        db.close()


async def test_capture_scoped_token_without_write_scope_is_forbidden(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            json={"text": "nope"},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "chat"},
        )
    assert r.status_code == 403
    db = factory()
    try:
        assert db.query(Note).count() == 0
    finally:
        db.close()


async def test_capture_rejects_empty_payload(cap_env):
    app, _ = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            json={},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "todos:write"},
        )
    assert r.status_code == 422


async def test_capture_multipart_form_with_file_folds_text(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            data={"title": "Doc", "text": "see attached", "url": "https://ex.test/z"},
            files={"files": ("note.txt", b"file body text", "text/plain")},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "todos:write"},
        )
    assert r.status_code == 201
    db = factory()
    try:
        note = db.query(Note).filter(Note.id == r.json()["id"]).one()
        assert "see attached" in note.content
        assert "file body text" in note.content
        assert "https://ex.test/z" in note.content
    finally:
        db.close()


async def test_capture_drops_non_http_url_scheme(cap_env):
    app, factory = cap_env
    async with _client(app) as c:
        r = await c.post(
            "/api/capture",
            json={"title": "t", "url": "javascript:alert(1)"},
            headers={"x-test-token-owner": "alice", "x-test-token-scopes": "todos:write"},
        )
    assert r.status_code == 201
    db = factory()
    try:
        note = db.query(Note).filter(Note.id == r.json()["id"]).one()
        assert "javascript:" not in (note.content or "")
    finally:
        db.close()
