"""routes/registry.py — single source of truth for router mounting.

app.py used to inline ~220 lines of ``app.include_router(setup_*_routes(...))``
calls. Five separate feature branches each appended a line there, so the file
was both oversized and a constant merge-conflict hotspot.

This module centralises that list. app.py builds a :class:`RegistrationContext`
of already-constructed dependencies and calls :func:`register_all`, which mounts
every router in :data:`ROUTER_SPECS` **in declaration order** (order matters:
e.g. ``codex`` borrows the ``email``/``memory``/``calendar``/``document``
routers, so it must be declared after them).

A future interface MR appends ONE :class:`RouterSpec` entry to
:data:`ROUTER_SPECS` instead of editing app.py.

Setup functions are imported lazily inside each builder (via importlib) so that
importing this module stays cheap and does not pull the whole route/service
graph — this keeps the registry independently testable.
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Sequence

from fastapi import APIRouter, FastAPI

logger = logging.getLogger(__name__)


@dataclass
class RegistrationContext:
    """Dependencies the ``setup_*_routes`` functions need, built by app.py.

    The manager/service fields are typed ``Any`` on purpose: importing their
    concrete types here would drag the heavy service graph into this module and
    defeat the lazy-import design. app.py constructs the real objects and passes
    them in; the builders below only read them.

    The trailing ``*_router`` / ``*_func`` fields are OUTPUTS: builders write the
    captured routers back onto the context so later builders (``codex``) and
    app.py (``upload_cleanup_func``) can read them.
    """

    # --- inputs (required) ---
    auth_manager: Any
    upload_handler: Any
    session_manager: Any
    session_config: dict[str, Any]
    webhook_manager: Any
    memory_manager: Any
    memory_vector: Any
    skills_manager: Any
    chat_handler: Any
    chat_processor: Any
    research_handler: Any
    config: Any
    preset_manager: Any
    rag_manager: Any
    rag_available: bool
    personal_docs_manager: Any
    model_discovery: Any
    tts_service: Any
    stt_service: Any
    task_scheduler: Any
    mcp_manager: Any
    api_key_manager: Any

    # --- outputs (captured during registration) ---
    upload_cleanup_func: Optional[Callable[..., Any]] = field(default=None)
    memory_router: Optional[APIRouter] = field(default=None)
    document_router: Optional[APIRouter] = field(default=None)
    calendar_router: Optional[APIRouter] = field(default=None)
    email_router: Optional[APIRouter] = field(default=None)


# A builder resolves and returns the router to mount for one spec. It may read
# from and write to the context (to share captured routers between entries).
Builder = Callable[[RegistrationContext], APIRouter]


@dataclass(frozen=True)
class RouterSpec:
    """One mountable router: a stable ``name`` plus its ``build`` callable."""

    name: str
    build: Builder


def _simple(
    module: str,
    func: str,
    args: Optional[Callable[[RegistrationContext], tuple]] = None,
    kwargs: Optional[Callable[[RegistrationContext], dict]] = None,
) -> Builder:
    """Build a router by lazily importing ``module.func`` and calling it.

    ``args``/``kwargs`` are callables that derive the call arguments from the
    context, so nothing is evaluated until :func:`register_all` runs.
    """

    def build(ctx: RegistrationContext) -> APIRouter:
        setup = getattr(importlib.import_module(module), func)
        call_args = args(ctx) if args else ()
        call_kwargs = kwargs(ctx) if kwargs else {}
        return setup(*call_args, **call_kwargs)

    return build


# --- builders that capture their router onto the context for later reuse ---


def _build_upload(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.upload_routes"), "setup_upload_routes")
    router, cleanup_func = setup(ctx.upload_handler)
    ctx.upload_cleanup_func = cleanup_func
    return router


def _build_memory(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.memory_routes"), "setup_memory_routes")
    ctx.memory_router = setup(
        ctx.memory_manager, ctx.session_manager, memory_vector=ctx.memory_vector
    )
    return ctx.memory_router


def _build_document(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.document_routes"), "setup_document_routes")
    ctx.document_router = setup(ctx.session_manager, ctx.upload_handler)
    return ctx.document_router


def _build_calendar(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.calendar_routes"), "setup_calendar_routes")
    ctx.calendar_router = setup()
    return ctx.calendar_router


def _build_email(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.email_routes"), "setup_email_routes")
    ctx.email_router = setup()
    return ctx.email_router


def _build_codex(ctx: RegistrationContext) -> APIRouter:
    setup = getattr(importlib.import_module("routes.codex_routes"), "setup_codex_routes")
    return setup(
        email_router=ctx.email_router,
        memory_router=ctx.memory_router,
        calendar_router=ctx.calendar_router,
        document_router=ctx.document_router,
    )


# Ordered registry. Declaration order == mount order and must be preserved:
# the original app.py mounted these in exactly this sequence.
ROUTER_SPECS: list[RouterSpec] = [
    RouterSpec("auth", _simple("routes.auth_routes", "setup_auth_routes", lambda c: (c.auth_manager,))),
    RouterSpec("upload", _build_upload),
    RouterSpec("emoji", _simple("routes.emoji_routes", "setup_emoji_routes")),
    RouterSpec(
        "session",
        _simple(
            "routes.session_routes",
            "setup_session_routes",
            lambda c: (c.session_manager, c.session_config),
            lambda c: {"webhook_manager": c.webhook_manager},
        ),
    ),
    RouterSpec("admin_wipe", _simple("routes.admin_wipe_routes", "setup_admin_wipe_routes", lambda c: (c.session_manager,))),
    RouterSpec("memory", _build_memory),
    RouterSpec("skills", _simple("routes.skills_routes", "setup_skills_routes", lambda c: (c.skills_manager,))),
    RouterSpec(
        "chat",
        _simple(
            "routes.chat_routes",
            "setup_chat_routes",
            lambda c: (
                c.session_manager, c.chat_handler, c.chat_processor,
                c.memory_manager, c.research_handler, c.upload_handler,
            ),
            lambda c: {
                "memory_vector": c.memory_vector,
                "webhook_manager": c.webhook_manager,
                "skills_manager": c.skills_manager,
            },
        ),
    ),
    RouterSpec("research", _simple("routes.research_routes", "setup_research_routes", lambda c: (c.research_handler,), lambda c: {"session_manager": c.session_manager})),
    RouterSpec("history", _simple("routes.history_routes", "setup_history_routes", lambda c: (c.session_manager,))),
    RouterSpec("search", _simple("routes.search_routes", "setup_search_routes", lambda c: (c.config,))),
    RouterSpec("preset", _simple("routes.preset_routes", "setup_preset_routes", lambda c: (c.preset_manager,))),
    RouterSpec("diagnostics", _simple("routes.diagnostics_routes", "setup_diagnostics_routes", lambda c: (c.rag_manager, c.rag_available, c.research_handler, c.memory_vector))),
    RouterSpec("cleanup", _simple("routes.cleanup_routes", "setup_cleanup_routes", lambda c: (c.session_manager,))),
    RouterSpec("personal", _simple("routes.personal_routes", "setup_personal_routes", lambda c: (c.personal_docs_manager, c.rag_manager, c.rag_available))),
    RouterSpec("pending", _simple("routes.pending_routes", "setup_pending_routes")),
    RouterSpec("autonomy", _simple("routes.autonomy_routes", "setup_autonomy_routes")),
    RouterSpec("embedding", _simple("routes.embedding_routes", "setup_embedding_routes")),
    RouterSpec("model", _simple("routes.model_routes", "setup_model_routes", lambda c: (c.model_discovery,))),
    RouterSpec("copilot", _simple("routes.copilot_routes", "setup_copilot_routes")),
    RouterSpec("chatgpt_subscription", _simple("routes.chatgpt_subscription_routes", "setup_chatgpt_subscription_routes")),
    RouterSpec("tts", _simple("routes.tts_routes", "setup_tts_routes", lambda c: (c.tts_service,))),
    RouterSpec("stt", _simple("routes.stt_routes", "setup_stt_routes", lambda c: (c.stt_service,))),
    RouterSpec("document", _build_document),
    RouterSpec("signature", _simple("routes.signature_routes", "setup_signature_routes")),
    RouterSpec("gallery", _simple("routes.gallery_routes", "setup_gallery_routes")),
    RouterSpec("editor_draft", _simple("routes.editor_draft_routes", "setup_editor_draft_routes")),
    RouterSpec("task", _simple("routes.task_routes", "setup_task_routes", lambda c: (c.task_scheduler,))),
    RouterSpec("assistant", _simple("routes.assistant_routes", "setup_assistant_routes", lambda c: (c.task_scheduler,))),
    RouterSpec("calendar", _build_calendar),
    RouterSpec("shell", _simple("routes.shell_routes", "setup_shell_routes")),
    RouterSpec("cookbook", _simple("routes.cookbook_routes", "setup_cookbook_routes")),
    RouterSpec("workspace", _simple("routes.workspace_routes", "setup_workspace_routes")),
    RouterSpec("hwfit", _simple("routes.hwfit_routes", "setup_hwfit_routes")),
    RouterSpec("compare", _simple("routes.compare_routes", "setup_compare_routes", lambda c: (c.session_manager,))),
    RouterSpec("prefs", _simple("routes.prefs_routes", "setup_prefs_routes")),
    RouterSpec("backup", _simple("routes.backup_routes", "setup_backup_routes", lambda c: (c.memory_manager, c.preset_manager, c.skills_manager))),
    RouterSpec("font", _simple("routes.font_routes", "setup_font_routes")),
    RouterSpec("mcp", _simple("routes.mcp_routes", "setup_mcp_routes", lambda c: (c.mcp_manager,))),
    RouterSpec("webhook", _simple("routes.webhook_routes", "setup_webhook_routes", lambda c: (c.webhook_manager, c.auth_manager, c.session_manager, c.api_key_manager))),
    RouterSpec("api_token", _simple("routes.api_token_routes", "setup_api_token_routes")),
    RouterSpec("note", _simple("routes.note_routes", "setup_note_routes", lambda c: (c.task_scheduler,))),
    RouterSpec("email", _build_email),
    RouterSpec("codex", _build_codex),
    RouterSpec("claude", _simple("routes.codex_routes", "setup_claude_routes")),
    RouterSpec("vault", _simple("routes.vault_routes", "setup_vault_routes")),
    RouterSpec("contacts", _simple("routes.contacts_routes", "setup_contacts_routes")),
    RouterSpec("companion", _simple("companion", "setup_companion_routes")),
]


def register_all(
    app: FastAPI,
    ctx: RegistrationContext,
    specs: Optional[Sequence[RouterSpec]] = None,
) -> None:
    """Mount every router in ``specs`` (default :data:`ROUTER_SPECS`) onto ``app``.

    Routers are mounted in declaration order. Each spec's ``build`` callable is
    invoked with ``ctx`` and must return an :class:`~fastapi.APIRouter`.
    """

    for spec in specs if specs is not None else ROUTER_SPECS:
        router = spec.build(ctx)
        app.include_router(router)
        logger.debug("Mounted router: %s", spec.name)
