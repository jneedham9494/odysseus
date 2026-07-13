# routes/voice_routes.py
"""Voice-loop API: audio-in -> STT -> agent -> streamed-text TTS -> audio-out.

This is an ENTRY POINT, so it is locked down:
  - Owner-only (admin / single-user mode) via ``owner_is_admin_or_single_user``.
  - Ships DISABLED: the ``voice_loop_enabled`` setting defaults to False, so the
    turn endpoint 404s until the operator explicitly turns it on.
  - Every action a voice turn triggers flows through ``stream_agent_loop``, which
    already routes mutating tools through the approval queue (``pending_actions``)
    and the taint model. Voice is NOT a side door around that boundary.
"""

import json
import logging

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from core.models import ChatMessage
from services.voice.voice_loop import run_voice_turn
from src.agent_loop import stream_agent_loop
from src.auth_helpers import effective_user
from src.tool_security import owner_is_admin_or_single_user
from src.upload_limits import STT_MAX_AUDIO_BYTES, read_upload_limited

logger = logging.getLogger(__name__)


def _voice_enabled() -> bool:
    """True only when the operator explicitly turned the voice loop on."""
    from src.settings import get_setting

    return bool(get_setting("voice_loop_enabled", False))


def setup_voice_routes(stt_service, tts_service, session_manager):
    """Build the voice router. Services are injected for testability."""
    router = APIRouter(prefix="/api/voice", tags=["voice"])

    def _require_owner(request: Request) -> str:
        owner = effective_user(request)
        if not owner_is_admin_or_single_user(owner):
            raise HTTPException(403, "Voice loop is owner-only.")
        return owner or ""

    @router.get("/status")
    async def voice_status(request: Request):
        """Report whether the voice loop is enabled and its services are ready."""
        _require_owner(request)
        return {
            "enabled": _voice_enabled(),
            "stt_available": bool(getattr(stt_service, "available", False)),
            "tts_available": bool(getattr(tts_service, "available", False)),
        }

    @router.post("/turn")
    async def voice_turn(
        request: Request,
        session: str = Form(...),
        file: UploadFile = File(...),
    ):
        """Run one spoken turn against an existing chat session."""
        owner = _require_owner(request)

        if not _voice_enabled():
            # Disabled-by-default: behave as if the route does not exist.
            raise HTTPException(404, "Voice loop is disabled.")
        if not getattr(stt_service, "available", False):
            raise HTTPException(503, "Speech-to-text is not configured.")

        try:
            sess = session_manager.get_session(session)
        except KeyError:
            raise HTTPException(404, f"Session '{session}' not found")

        # Ownership: never let a voice caller drive another user's session.
        sess_owner = getattr(sess, "owner", None)
        if sess_owner and owner and sess_owner != owner:
            raise HTTPException(403, "You do not own this session.")

        if not (getattr(sess, "model", "") or "").strip() or not (
            getattr(sess, "endpoint_url", "") or ""
        ).strip():
            raise HTTPException(400, "This session has no model selected.")

        audio_bytes = await read_upload_limited(file, STT_MAX_AUDIO_BYTES, "Audio file")
        if not audio_bytes:
            raise HTTPException(400, "Empty audio file.")

        async def transcribe(data: bytes):
            # Blocking Whisper call -> offload so it can't stall the event loop.
            return await run_in_threadpool(stt_service.transcribe, data)

        async def synthesize(text: str):
            if not getattr(tts_service, "available", False):
                return None
            return await run_in_threadpool(tts_service.synthesize, text)

        async def agent_stream(user_text: str):
            # Persist the spoken user turn, then run the SAME agent loop the web
            # path uses — so approval + taint gating apply identically.
            sess.add_message(ChatMessage("user", user_text, metadata={"source": "voice"}))
            messages = sess.get_context_messages()
            async for chunk in stream_agent_loop(
                sess.endpoint_url,
                sess.model,
                messages,
                headers=sess.headers,
                session_id=session,
                owner=owner or None,
            ):
                yield chunk

        async def event_stream():
            reply_parts = []
            try:
                async for event in run_voice_turn(
                    audio_bytes,
                    transcribe=transcribe,
                    agent_stream=agent_stream,
                    synthesize=synthesize,
                ):
                    if event.get("type") == "text_delta":
                        reply_parts.append(event["text"])
                    yield f"data: {json.dumps(event)}\n\n"
            except Exception as exc:  # last-resort guard around the generator
                logger.error("Voice turn stream failed: %s", exc, exc_info=True)
                yield f'data: {json.dumps({"type": "error", "stage": "stream", "message": "Voice turn failed."})}\n\n'
            else:
                reply = "".join(reply_parts).strip()
                if reply:
                    sess.add_message(
                        ChatMessage("assistant", reply, metadata={"source": "voice"})
                    )
            yield "data: [DONE]\n\n"

        return StreamingResponse(event_stream(), media_type="text/event-stream")

    return router
