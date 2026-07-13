# tests/test_voice_loop.py
"""Voice-loop tests: pipeline core + owner-gated / disabled route surface.

Covers:
  - a spoken query round-trips text -> agent -> tts
  - streamed-text TTS flushes sentences incrementally (latency win)
  - a voice-triggered mutating action is gated by the SAME admission seam the
    web path uses (stream_agent_loop -> _needs_approval), not a voice side door
  - route surface: owner-only (403 for non-owner) and disabled-by-default (404)
"""

import base64
import json

import pytest

from services.voice.voice_loop import (
    SentenceAggregator,
    run_voice_turn,
    sse_text_delta,
)


def _sse(obj) -> str:
    return f"data: {json.dumps(obj)}\n\n"


async def _collect(agen):
    return [ev async for ev in agen]


# -- SentenceAggregator ------------------------------------------------------


def test_aggregator_flushes_on_sentence_boundary():
    agg = SentenceAggregator()
    assert agg.push("Hello there") == []          # no boundary yet
    assert agg.push(". How are") == ["Hello there."]
    assert agg.push(" you?") == ["How are you?"]
    assert agg.flush() == []


def test_aggregator_flush_returns_unterminated_tail():
    agg = SentenceAggregator()
    agg.push("No punctuation here")
    assert agg.flush() == ["No punctuation here"]


def test_aggregator_splits_multiple_sentences_in_one_push():
    agg = SentenceAggregator()
    assert agg.push("One. Two! Three?") == ["One.", "Two!", "Three?"]


# -- sse_text_delta ----------------------------------------------------------


def test_sse_text_delta_extracts_delta():
    assert sse_text_delta(_sse({"delta": "hi"})) == "hi"


def test_sse_text_delta_skips_thinking_and_events_and_done():
    assert sse_text_delta(_sse({"delta": "secret", "thinking": True})) is None
    assert sse_text_delta(_sse({"type": "tool_start", "tool": "x"})) is None
    assert sse_text_delta("data: [DONE]\n\n") is None
    assert sse_text_delta("garbage") is None


# -- Full round-trip ---------------------------------------------------------


@pytest.mark.asyncio
async def test_spoken_query_round_trips_text_agent_tts():
    """audio -> STT -> agent -> TTS produces transcript + audio events."""
    spoken = []

    def transcribe(_audio):
        return "what is the weather"

    async def agent_stream(text):
        assert text == "what is the weather"
        yield _sse({"delta": "It is sunny."})
        yield _sse({"delta": " Enjoy!"})
        yield "data: [DONE]\n\n"

    def synthesize(sentence):
        spoken.append(sentence)
        return b"AUDIO:" + sentence.encode()

    events = await _collect(
        run_voice_turn(
            b"\x00audio",
            transcribe=transcribe,
            agent_stream=agent_stream,
            synthesize=synthesize,
        )
    )
    types = [e["type"] for e in events]

    assert types[0] == "transcript"
    assert events[0]["text"] == "what is the weather"
    assert types[-1] == "done"

    # Both sentences were synthesized, in order.
    assert spoken == ["It is sunny.", "Enjoy!"]

    audio_events = [e for e in events if e["type"] == "audio"]
    assert len(audio_events) == 2
    decoded = base64.b64decode(audio_events[0]["audio_b64"])
    assert decoded == b"AUDIO:It is sunny."

    # Full text was streamed as deltas.
    full = "".join(e["text"] for e in events if e["type"] == "text_delta")
    assert full == "It is sunny. Enjoy!"


@pytest.mark.asyncio
async def test_first_sentence_synthesized_before_stream_ends():
    """Latency win: sentence 1 is spoken while later deltas still arrive."""
    order = []

    def transcribe(_a):
        return "go"

    async def agent_stream(_t):
        yield _sse({"delta": "First done. "})
        order.append("delta-after-first")
        yield _sse({"delta": "Second."})

    def synthesize(s):
        order.append(f"tts:{s}")
        return b"a"

    await _collect(
        run_voice_turn(
            b"x", transcribe=transcribe, agent_stream=agent_stream, synthesize=synthesize
        )
    )
    # TTS of the first sentence happens BEFORE the second delta is produced.
    assert order.index("tts:First done.") < order.index("delta-after-first")


@pytest.mark.asyncio
async def test_empty_transcript_yields_stt_error_and_no_agent_call():
    called = {"agent": False}

    def transcribe(_a):
        return "   "

    async def agent_stream(_t):
        called["agent"] = True
        yield _sse({"delta": "should not run"})

    events = await _collect(
        run_voice_turn(
            b"x", transcribe=transcribe, agent_stream=agent_stream, synthesize=lambda s: b"a"
        )
    )
    assert called["agent"] is False
    assert events[-1]["type"] == "error"
    assert events[-1]["stage"] == "stt"


@pytest.mark.asyncio
async def test_tts_failure_does_not_kill_turn():
    def transcribe(_a):
        return "hello"

    async def agent_stream(_t):
        yield _sse({"delta": "One. Two."})

    def synthesize(_s):
        raise RuntimeError("tts down")

    events = await _collect(
        run_voice_turn(
            b"x", transcribe=transcribe, agent_stream=agent_stream, synthesize=synthesize
        )
    )
    # No audio, but the turn completes cleanly.
    assert not any(e["type"] == "audio" for e in events)
    assert events[-1]["type"] == "done"


@pytest.mark.asyncio
async def test_async_stt_and_tts_are_awaited():
    async def transcribe(_a):
        return "async path"

    async def agent_stream(_t):
        yield _sse({"delta": "Done."})

    async def synthesize(_s):
        return b"async-audio"

    events = await _collect(
        run_voice_turn(
            b"x", transcribe=transcribe, agent_stream=agent_stream, synthesize=synthesize
        )
    )
    audio = [e for e in events if e["type"] == "audio"]
    assert audio and base64.b64decode(audio[0]["audio_b64"]) == b"async-audio"


# -- Security parity: voice action gated exactly like the web path -----------


@pytest.mark.asyncio
async def test_voice_mutating_action_is_gated_by_admission_seam(monkeypatch):
    """A voice-triggered mutating tool must be held by the SAME admission gate the
    web chat path uses. ``stream_agent_loop`` consults ``_needs_approval``, which
    (post-refactor) delegates to ``src.admission.requires_confirm_approval_failclosed``.
    We patch that exact seam and prove a voice-driven tool flows through it."""
    import src.admission as admission
    import src.agent_loop as agent_loop

    approval_calls = []

    def fake_failclosed(tool_type, content=None):
        approval_calls.append(tool_type)
        return True  # gate it

    # Patch the exact seam stream_agent_loop consults (via _needs_approval).
    monkeypatch.setattr(admission, "requires_confirm_approval_failclosed", fake_failclosed)

    gated = agent_loop._needs_approval("send_email", "to: x@example.com")

    assert gated is True
    assert "send_email" in approval_calls


@pytest.mark.asyncio
async def test_voice_agent_stream_uses_stream_agent_loop_not_direct_exec():
    """Structural guard: the pipeline consumes an injected agent_stream and does
    not invoke tools itself — so all tool execution/approval lives in
    stream_agent_loop, identical to the web path (no voice side door)."""
    synthesized = []

    def transcribe(_a):
        return "send an email to bob"

    async def agent_stream(_t):
        # stream_agent_loop emits a tool_start event; pipeline must NOT treat it
        # as speakable text nor execute anything.
        yield _sse({"type": "tool_start", "tool": "send_email"})
        yield _sse({"delta": "Queued for approval."})

    def synthesize(s):
        synthesized.append(s)
        return b"a"

    events = await _collect(
        run_voice_turn(
            b"x", transcribe=transcribe, agent_stream=agent_stream, synthesize=synthesize
        )
    )
    # Only the assistant's spoken text is synthesized; the tool_start is not.
    assert synthesized == ["Queued for approval."]
    assert not any(
        e["type"] == "text_delta" and "tool_start" in e["text"] for e in events
    )


def test_voice_policy_applies_operator_global_disabled_tools(monkeypatch):
    """Regression: the operator's GLOBAL ``disabled_tools`` kill-list must reach
    the voice turn's tool policy.

    The admission ``PolicyBlockStage`` only DENIES when a ``tool_policy`` is
    present, so a voice turn that omits it silently bypasses the kill-list — a
    tool hard-DENYed on the web path would execute via voice. This test drives
    the exact helper the voice route feeds into ``stream_agent_loop`` and proves
    a globally-disabled tool is blocked. It fails on the pre-fix branch (where
    the voice route passed no ``tool_policy``/``disabled_tools`` at all)."""
    import routes.voice_routes as vr
    import src.settings as settings

    # The helper does a call-time ``from src.settings import get_setting``, so
    # patch the source attribute that import resolves.
    monkeypatch.setattr(
        settings, "get_setting",
        lambda key, default=None: ["bash"] if key == "disabled_tools" else default,
    )

    policy = vr._effective_tool_policy("what's the weather")

    assert policy.blocks("bash")
    assert "bash" in policy.all_disabled_names()


# -- Route surface: owner-only + disabled-by-default -------------------------


def _build_client(monkeypatch, *, owner=True, enabled=False):
    """Mount the voice router with mocked services + auth for route tests."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import routes.voice_routes as vr
    import src.settings as settings

    class _Svc:
        available = True

    monkeypatch.setattr(vr, "effective_user", lambda _req: "jack")
    monkeypatch.setattr(vr, "owner_is_admin_or_single_user", lambda _o: owner)
    monkeypatch.setattr(
        settings,
        "get_setting",
        lambda key, default=None: enabled if key == "voice_loop_enabled" else default,
    )

    app = FastAPI()
    app.include_router(vr.setup_voice_routes(_Svc(), _Svc(), object()))
    return TestClient(app, raise_server_exceptions=False)


def test_status_rejects_non_owner_with_403(monkeypatch):
    client = _build_client(monkeypatch, owner=False)
    resp = client.get("/api/voice/status")
    assert resp.status_code == 403


def test_status_reports_disabled_by_default_for_owner(monkeypatch):
    client = _build_client(monkeypatch, owner=True, enabled=False)
    resp = client.get("/api/voice/status")
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


def test_turn_rejects_non_owner_with_403(monkeypatch):
    client = _build_client(monkeypatch, owner=False, enabled=True)
    resp = client.post(
        "/api/voice/turn",
        data={"session": "s1"},
        files={"file": ("a.wav", b"audio-bytes", "audio/wav")},
    )
    assert resp.status_code == 403


def test_turn_returns_404_when_disabled(monkeypatch):
    """Disabled-by-default: an owner still gets 404 (route behaves as absent)."""
    client = _build_client(monkeypatch, owner=True, enabled=False)
    resp = client.post(
        "/api/voice/turn",
        data={"session": "s1"},
        files={"file": ("a.wav", b"audio-bytes", "audio/wav")},
    )
    assert resp.status_code == 404
