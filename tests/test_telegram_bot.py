"""Tests for the owner-only Telegram bridge (src/telegram_bot.py).

The aiogram package is not a hard dependency, so we inject a minimal fake
``aiogram`` into sys.modules BEFORE importing the bot. The agent loop and the
approval path are mocked so nothing hits the network or a real model.
"""
import asyncio
import sys
import types
from unittest.mock import MagicMock

# ── Fake aiogram (must be registered before importing telegram_bot's adapters) ──


class _FakeMarkup:
    def __init__(self, inline_keyboard):
        self.inline_keyboard = inline_keyboard


class _FakeButton:
    def __init__(self, text, callback_data):
        self.text = text
        self.callback_data = callback_data


class _FakeDispatcher:
    def __init__(self):
        self.message_handlers = []
        self.callback_handlers = []

    def message(self, *args, **kwargs):
        def deco(fn):
            self.message_handlers.append(fn)
            return fn
        return deco

    def callback_query(self, *args, **kwargs):
        def deco(fn):
            self.callback_handlers.append(fn)
            return fn
        return deco


def _install_fake_aiogram():
    aiogram = types.ModuleType("aiogram")
    aiogram.Bot = MagicMock(name="Bot")
    aiogram.Dispatcher = _FakeDispatcher
    aiogram.F = MagicMock(name="F")
    types_mod = types.ModuleType("aiogram.types")
    types_mod.CallbackQuery = object
    types_mod.InlineKeyboardButton = _FakeButton
    types_mod.InlineKeyboardMarkup = _FakeMarkup
    types_mod.Message = object
    aiogram.types = types_mod
    sys.modules["aiogram"] = aiogram
    sys.modules["aiogram.types"] = types_mod


_install_fake_aiogram()

from src import telegram_bot as tb  # noqa: E402
from src import telegram_runtime as trt  # noqa: E402

ALLOWED = 4242
OTHER = 9999


def _cfg(token="tok", allowed=ALLOWED, owner="jack"):
    return tb.TelegramConfig(token=token, allowed_user_id=allowed, app_owner=owner)


# ── config / auth ──

def test_config_disabled_when_no_token():
    cfg = _cfg(token="")
    assert cfg.enabled is False


def test_config_disabled_when_no_allowed_user_id():
    cfg = _cfg(allowed=None)
    assert cfg.enabled is False


def test_is_authorized_only_for_configured_owner():
    cfg = _cfg()
    assert tb.is_authorized(cfg, ALLOWED) is True
    assert tb.is_authorized(cfg, OTHER) is False
    assert tb.is_authorized(cfg, None) is False


def test_disabled_bot_authorizes_nobody():
    cfg = _cfg(token="")
    assert tb.is_authorized(cfg, ALLOWED) is False


# ── message routing ──

def test_message_from_allowed_user_routes_to_agent_and_replies(monkeypatch):
    calls = {}

    async def fake_turn(text, *, owner, session_id):
        calls["text"] = text
        calls["owner"] = owner
        calls["session_id"] = session_id
        return "agent says hi"

    monkeypatch.setattr(tb, "run_agent_turn", fake_turn)
    reply = asyncio.run(tb.handle_message(_cfg(), ALLOWED, "hello there"))

    assert reply == "agent says hi"
    assert calls["text"] == "hello there"
    assert calls["owner"] == "jack"
    assert calls["session_id"] == "telegram-4242"


def test_message_from_non_allowed_id_is_ignored(monkeypatch):
    called = {"n": 0}

    async def fake_turn(text, *, owner, session_id):
        called["n"] += 1
        return "should not happen"

    monkeypatch.setattr(tb, "run_agent_turn", fake_turn)
    reply = asyncio.run(tb.handle_message(_cfg(), OTHER, "hello"))

    assert reply is None
    assert called["n"] == 0


def test_empty_message_from_owner_gets_prompt(monkeypatch):
    async def fake_turn(text, *, owner, session_id):  # pragma: no cover
        raise AssertionError("agent should not run on empty text")

    monkeypatch.setattr(tb, "run_agent_turn", fake_turn)
    reply = asyncio.run(tb.handle_message(_cfg(), ALLOWED, "   "))
    assert "message" in reply.lower()


# ── approval buttons ──

def test_callback_round_trip_keyboard_to_parse():
    keyboard = tb.build_pending_keyboard("abc123def456")
    (approve_label, approve_cb), (reject_label, reject_cb) = keyboard[0]
    assert tb.parse_callback(approve_cb) == ("approve", "abc123def456")
    assert tb.parse_callback(reject_cb) == ("reject", "abc123def456")
    assert tb.parse_callback("garbage") is None


def test_approve_button_maps_to_pending_id_and_calls_approve_path(monkeypatch):
    import routes.pending_routes as pr
    seen = {}

    async def fake_approve(pid, owner):
        seen["pid"] = pid
        seen["owner"] = owner
        return {"ok": True, "id": pid, "tool_type": "write_file", "result": {}}

    async def fake_reject(pid, owner):  # pragma: no cover - not used here
        raise AssertionError("reject should not be called for an approve button")

    monkeypatch.setattr(pr, "approve_pending", fake_approve)
    monkeypatch.setattr(pr, "reject_pending", fake_reject)

    reply = asyncio.run(tb.handle_callback(_cfg(), ALLOWED, "approve:pid789"))

    assert seen["pid"] == "pid789"
    assert seen["owner"] == "jack"
    assert "Approved" in reply and "write_file" in reply


def test_reject_button_calls_reject_path(monkeypatch):
    import routes.pending_routes as pr
    seen = {}

    async def fake_reject(pid, owner):
        seen["pid"] = pid
        return {"ok": True, "id": pid, "status": "rejected"}

    monkeypatch.setattr(pr, "reject_pending", fake_reject)
    reply = asyncio.run(tb.handle_callback(_cfg(), ALLOWED, "reject:pidZZ"))

    assert seen["pid"] == "pidZZ"
    assert "Rejected" in reply


def test_callback_from_non_allowed_id_is_ignored(monkeypatch):
    import routes.pending_routes as pr

    async def fake_approve(pid, owner):  # pragma: no cover
        raise AssertionError("approve must not run for unauthorized user")

    monkeypatch.setattr(pr, "approve_pending", fake_approve)
    reply = asyncio.run(tb.handle_callback(_cfg(), OTHER, "approve:pid789"))
    assert reply is None


# ── agent-turn aggregation (mock the agent loop) ──

def test_run_agent_turn_aggregates_visible_deltas(monkeypatch):
    async def fake_stream(**kwargs):
        yield 'data: {"delta": "Hel"}'
        yield 'data: {"delta": "lo", "thinking": true}'   # hidden reasoning
        yield 'data: {"delta": " world"}'
        yield 'data: [DONE]'

    fake_agent = types.ModuleType("src.agent_loop")
    fake_agent.stream_agent_loop = fake_stream
    monkeypatch.setitem(sys.modules, "src.agent_loop", fake_agent)
    monkeypatch.setattr(
        tb, "_load_history", lambda owner, sid, text: [{"role": "user", "content": text}]
    )
    monkeypatch.setattr(tb, "_save_reply", lambda sid, text: None)

    import src.endpoint_resolver as er
    monkeypatch.setattr(er, "resolve_endpoint", lambda *a, **k: ("http://x/v1", "m", {}))

    out = asyncio.run(tb.run_agent_turn("hi", owner="jack", session_id="telegram-1"))
    assert out == "Hel world"  # thinking delta excluded


def test_run_agent_turn_without_model_returns_notice(monkeypatch):
    import src.endpoint_resolver as er
    monkeypatch.setattr(er, "resolve_endpoint", lambda *a, **k: (None, None, None))
    out = asyncio.run(tb.run_agent_turn("hi", owner="jack", session_id="telegram-1"))
    assert "model" in out.lower()


# ── start hook: disabled by default ──

def test_start_telegram_bot_disabled_returns_none():
    assert trt.start_telegram_bot(_cfg(token="")) is None


def test_start_telegram_bot_no_allowed_id_returns_none():
    assert trt.start_telegram_bot(_cfg(allowed=None)) is None


# ── aiogram adapter wiring (mock the Bot) ──

def test_dispatcher_message_handler_replies_via_bot(monkeypatch):
    async def fake_turn(text, *, owner, session_id):
        return "bot reply"

    monkeypatch.setattr(tb, "run_agent_turn", fake_turn)
    dp = trt.build_dispatcher(_cfg())

    answered = []

    class FakeUser:
        id = ALLOWED

    class FakeMessage:
        from_user = FakeUser()
        text = "ping"

        async def answer(self, text, reply_markup=None):
            answered.append(text)

    general_handler = dp.message_handlers[-1]
    asyncio.run(general_handler(FakeMessage()))
    assert answered == ["bot reply"]


def test_dispatcher_callback_handler_answers_and_replies(monkeypatch):
    import routes.pending_routes as pr

    async def fake_approve(pid, owner):
        return {"ok": True, "id": pid, "tool_type": "bash", "result": {}}

    monkeypatch.setattr(pr, "approve_pending", fake_approve)
    dp = trt.build_dispatcher(_cfg())

    replies = []
    acked = {"n": 0}

    class FakeUser:
        id = ALLOWED

    class FakeInner:
        async def answer(self, text, reply_markup=None):
            replies.append(text)

    class FakeCallback:
        from_user = FakeUser()
        data = "approve:pidABC"
        message = FakeInner()

        async def answer(self, *a, **k):
            acked["n"] += 1

    handler = dp.callback_handlers[0]
    asyncio.run(handler(FakeCallback()))
    assert acked["n"] == 1
    assert replies and "Approved" in replies[0]
