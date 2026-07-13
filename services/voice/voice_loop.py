# services/voice/voice_loop.py
"""Voice-turn pipeline core: STT -> agent stream -> streamed-text TTS.

This module is the *pure, dependency-injected* heart of the voice loop. It does
no I/O of its own: the caller supplies ``transcribe`` (bytes -> text),
``agent_stream`` (text -> async SSE chunks) and ``synthesize`` (text -> audio
bytes). That keeps it fully unit-testable with mocks and keeps the security
boundary in the route layer / ``stream_agent_loop`` (approval + taint) rather
than here.

Latency win: text deltas are aggregated into sentences and each completed
sentence is handed to TTS immediately, so the first sentence is spoken while the
model is still generating the rest.
"""

import base64
import inspect
import json
import logging
import re
from typing import AsyncGenerator, Awaitable, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

# Callable contracts (sync or async both accepted).
TranscribeFn = Callable[[bytes], Union[Optional[str], Awaitable[Optional[str]]]]
SynthesizeFn = Callable[[str], Union[Optional[bytes], Awaitable[Optional[bytes]]]]
AgentStreamFn = Callable[[str], AsyncGenerator[str, None]]

MAX_TRANSCRIPT_CHARS = 8000


class SentenceAggregator:
    """Buffers streamed text and flushes complete sentences.

    A sentence boundary is ``.``, ``!``, ``?`` or a newline followed by
    whitespace or end-of-buffer. The lazy match flushes the *first* complete
    sentence as early as possible (low latency) without greedily merging
    several sentences into one TTS call.
    """

    _BOUNDARY = re.compile(r".*?[.!?\n]+(?:\s|$)", re.DOTALL)

    def __init__(self) -> None:
        self._buf = ""

    def push(self, text: str) -> List[str]:
        """Add streamed text; return any newly-completed sentences."""
        if not text:
            return []
        self._buf += text
        out: List[str] = []
        while True:
            match = self._BOUNDARY.match(self._buf)
            if not match:
                break
            sentence = match.group(0).strip()
            if sentence:
                out.append(sentence)
            self._buf = self._buf[match.end():]
        return out

    def flush(self) -> List[str]:
        """Return any trailing text not terminated by punctuation."""
        remainder = self._buf.strip()
        self._buf = ""
        return [remainder] if remainder else []


def sse_text_delta(chunk: str) -> Optional[str]:
    """Extract a user-visible text delta from a ``stream_agent_loop`` SSE line.

    Returns the delta string, or ``None`` for non-text events (tool_start,
    metrics, [DONE], reasoning/thinking tokens, malformed lines). Mirrors the
    filtering the web chat_stream path applies so voice hears the same text the
    UI shows.
    """
    if not isinstance(chunk, str) or not chunk.startswith("data: "):
        return None
    payload = chunk[6:].strip()
    if not payload or payload == "[DONE]":
        return None
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    if "delta" in data and not data.get("thinking"):
        delta = data["delta"]
        return delta if isinstance(delta, str) else None
    return None


async def _maybe_await(value):
    """Await ``value`` if it is awaitable, else return it as-is.

    Lets callers pass either sync services (``stt.transcribe``) or async /
    thread-offloaded wrappers without the core caring which.
    """
    if inspect.isawaitable(value):
        return await value
    return value


async def _speak(text: str, synthesize: SynthesizeFn) -> AsyncGenerator[Dict, None]:
    """Synthesize one sentence and yield an ``audio`` event (skips on failure)."""
    try:
        audio = await _maybe_await(synthesize(text))
    except Exception as exc:  # synthesis must never kill the turn
        logger.warning("TTS synthesis failed for sentence (%d chars): %s", len(text), exc)
        return
    if not audio:
        return
    yield {
        "type": "audio",
        "text": text,
        "audio_b64": base64.b64encode(audio).decode("ascii"),
    }


async def run_voice_turn(
    audio_bytes: bytes,
    *,
    transcribe: TranscribeFn,
    agent_stream: AgentStreamFn,
    synthesize: SynthesizeFn,
    extract_delta: Callable[[str], Optional[str]] = sse_text_delta,
) -> AsyncGenerator[Dict, None]:
    """Run one full voice turn, yielding pipeline events.

    Event shapes (all dicts):
      - {"type": "transcript", "text": str}       once, after STT
      - {"type": "text_delta", "text": str}       per model text chunk
      - {"type": "audio", "text": str, "audio_b64": str}  per spoken sentence
      - {"type": "error", "stage": str, "message": str}   terminal on failure
      - {"type": "done"}                            terminal on success

    The caller is responsible for authentication, the enabled-setting gate, and
    for wiring ``agent_stream`` to ``stream_agent_loop`` (which enforces the
    approval queue + taint model). This function does not bypass that boundary.
    """
    if not audio_bytes:
        yield {"type": "error", "stage": "stt", "message": "No audio provided."}
        return

    try:
        text = await _maybe_await(transcribe(audio_bytes))
    except Exception as exc:
        logger.error("STT transcription raised: %s", exc, exc_info=True)
        yield {"type": "error", "stage": "stt", "message": "Transcription failed."}
        return

    if not text or not text.strip():
        yield {"type": "error", "stage": "stt", "message": "No speech detected."}
        return

    text = text.strip()[:MAX_TRANSCRIPT_CHARS]
    yield {"type": "transcript", "text": text}

    aggregator = SentenceAggregator()
    try:
        async for chunk in agent_stream(text):
            delta = extract_delta(chunk)
            if not delta:
                continue
            yield {"type": "text_delta", "text": delta}
            for sentence in aggregator.push(delta):
                async for event in _speak(sentence, synthesize):
                    yield event
    except Exception as exc:
        logger.error("Agent stream raised during voice turn: %s", exc, exc_info=True)
        yield {"type": "error", "stage": "agent", "message": "Agent processing failed."}
        return

    for sentence in aggregator.flush():
        async for event in _speak(sentence, synthesize):
            yield event

    yield {"type": "done"}
