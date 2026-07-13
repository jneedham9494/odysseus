"""Characterization tests for routes/registry.py (refactor/router-registry).

These tests pin the behaviour-preserving contract of moving app.py's inline
``app.include_router(...)`` block into a declared registry:

  * the exact set + order of routers is unchanged (frozen snapshot);
  * ``register_all`` mounts every declared router, in order;
  * adding one entry mounts exactly one more router;
  * the captured-router plumbing (upload cleanup handle, codex borrowing the
    email/memory/calendar/document routers) still works.

They import ``routes.registry`` in isolation (no heavy service graph) by faking
the lazily-imported ``setup_*_routes`` leaf functions, so they run in the light
test venv and pass both before and after the refactor's app.py rewrite.
"""

from __future__ import annotations

import importlib
from unittest.mock import MagicMock

from fastapi import APIRouter, FastAPI

from routes import registry
from routes.registry import (
    RegistrationContext,
    RouterSpec,
    ROUTER_SPECS,
    register_all,
)


# The routers app.py mounted before the refactor, in mount order. This is the
# characterization snapshot: it must not change without an intentional edit.
EXPECTED_ORDER: list[str] = [
    "auth", "upload", "emoji", "session", "admin_wipe", "memory",
    "skills", "chat", "research", "history", "search", "preset",
    "diagnostics", "cleanup", "personal", "pending", "autonomy",
    "embedding", "model", "copilot", "chatgpt_subscription", "tts",
    "stt", "document", "signature", "gallery", "editor_draft", "task",
    "assistant", "calendar", "shell", "cookbook", "workspace", "hwfit",
    "compare", "prefs", "backup", "font", "mcp", "webhook", "api_token",
    "note", "email", "codex", "claude", "vault", "contacts",
    "companion", "connector_ingest", "pwa", "capture", "voice",
]


def _make_ctx() -> RegistrationContext:
    """A context with mock dependencies — builders only pass these through."""
    fields = {
        "auth_manager", "upload_handler", "session_manager", "webhook_manager",
        "memory_manager", "memory_vector", "skills_manager", "chat_handler",
        "chat_processor", "research_handler", "config", "preset_manager",
        "rag_manager", "personal_docs_manager", "model_discovery",
        "tts_service", "stt_service", "task_scheduler", "mcp_manager",
        "api_key_manager",
    }
    kwargs = {name: MagicMock(name=name) for name in fields}
    kwargs["session_config"] = {}
    kwargs["rag_available"] = True
    return RegistrationContext(**kwargs)


class _FakeModule:
    """Stands in for a real ``routes.*`` module: any attribute is a fake
    ``setup_*`` function that returns a uniquely-tagged APIRouter and records
    the call so tests can assert wiring/order."""

    def __init__(self, name: str, calls: list) -> None:
        self._name = name
        self._calls = calls

    def __getattr__(self, func: str):
        def setup(*args, **kwargs):
            self._calls.append((self._name, func, args, kwargs))
            router = APIRouter()
            path = f"/__{self._name}__.{func}"

            @router.get(path)
            async def _handler() -> dict:
                return {}

            # setup_upload_routes returns (router, cleanup_func).
            if func == "setup_upload_routes":
                return router, ("cleanup", self._name)
            return router

        return setup


def _collect_paths(routes) -> set:
    """Recursively collect route paths, tolerating Starlette's lazy
    ``_IncludedRouter`` wrapper (which exposes routes via ``original_router``)."""
    paths: set = set()
    for route in routes:
        path = getattr(route, "path", None)
        if path:
            paths.add(path)
        sub = getattr(route, "routes", None)
        if sub:
            paths |= _collect_paths(sub)
        original = getattr(route, "original_router", None)
        if original is not None and getattr(original, "routes", None):
            paths |= _collect_paths(original.routes)
    return paths


def _install_fake_imports(monkeypatch) -> list:
    calls: list = []
    monkeypatch.setattr(
        registry.importlib,
        "import_module",
        lambda name: _FakeModule(name, calls),
    )
    return calls


# --------------------------------------------------------------------------- #
# Snapshot: router set + order preserved
# --------------------------------------------------------------------------- #

def test_router_specs_match_frozen_order():
    assert [spec.name for spec in ROUTER_SPECS] == EXPECTED_ORDER


def test_router_spec_names_are_unique():
    names = [spec.name for spec in ROUTER_SPECS]
    assert len(names) == len(set(names))


# --------------------------------------------------------------------------- #
# register_all mounts every declared router, in order (real ROUTER_SPECS,
# fake leaf setup functions) — the "every route mounted before is still
# mounted after" invariant.
# --------------------------------------------------------------------------- #

def test_register_all_mounts_every_router(monkeypatch):
    _install_fake_imports(monkeypatch)
    app = FastAPI()
    before = _collect_paths(app.routes)

    register_all(app, _make_ctx())

    mounted = _collect_paths(app.routes) - before
    # exactly one distinct router path mounted per declared spec
    assert len(mounted) == len(ROUTER_SPECS)
    assert all(path.startswith("/__") for path in mounted)


def test_register_all_preserves_declaration_order(monkeypatch):
    calls = _install_fake_imports(monkeypatch)
    register_all(FastAPI(), _make_ctx())
    # codex must be built AFTER email (it borrows the email router).
    built_names = [c[0] for c in calls]
    assert built_names.index("routes.email_routes") < built_names.index(
        "routes.codex_routes"
    )


# --------------------------------------------------------------------------- #
# Captured-router plumbing
# --------------------------------------------------------------------------- #

def test_upload_cleanup_func_captured(monkeypatch):
    _install_fake_imports(monkeypatch)
    ctx = _make_ctx()
    register_all(FastAPI(), ctx)
    assert ctx.upload_cleanup_func == ("cleanup", "routes.upload_routes")


def test_codex_borrows_previously_built_routers(monkeypatch):
    calls = _install_fake_imports(monkeypatch)
    ctx = _make_ctx()
    register_all(FastAPI(), ctx)
    # email/memory/calendar/document routers were captured on the context...
    assert ctx.email_router is not None
    assert ctx.memory_router is not None
    assert ctx.calendar_router is not None
    assert ctx.document_router is not None
    # ...and codex received them (not None) via its kwargs.
    codex_call = next(c for c in calls if c[0] == "routes.codex_routes"
                      and c[1] == "setup_codex_routes")
    kwargs = codex_call[3]
    for key in ("email_router", "memory_router", "calendar_router",
                "document_router"):
        assert kwargs[key] is not None


# --------------------------------------------------------------------------- #
# A new entry in the registry mounts its router
# --------------------------------------------------------------------------- #

def test_new_registry_entry_mounts_one_more_router(monkeypatch):
    _install_fake_imports(monkeypatch)
    app = FastAPI()

    base = _make_ctx()
    register_all(app, base)
    baseline = _collect_paths(app.routes)

    def _extra_builder(ctx: RegistrationContext) -> APIRouter:
        router = APIRouter()

        @router.get("/__brand_new_feature__")
        async def _h() -> dict:
            return {}

        return router

    extended = list(ROUTER_SPECS) + [RouterSpec("brand_new", _extra_builder)]
    app2 = FastAPI()
    register_all(app2, _make_ctx(), specs=extended)
    after = _collect_paths(app2.routes)

    added = after - baseline
    assert added == {"/__brand_new_feature__"}


def test_register_all_accepts_custom_spec_list():
    """register_all works on an arbitrary spec list (used by feature tests)."""
    app = FastAPI()

    def build_a(ctx):
        r = APIRouter()
        r.add_api_route("/a", lambda: {})
        return r

    def build_b(ctx):
        r = APIRouter()
        r.add_api_route("/b", lambda: {})
        return r

    specs = [RouterSpec("a", build_a), RouterSpec("b", build_b)]
    register_all(app, _make_ctx(), specs=specs)
    paths = _collect_paths(app.routes)
    assert {"/a", "/b"} <= paths
