"""Owner-only Telegram bridge to the Argos agent (aiogram long-poll).

Lets the configured OWNER talk to the assistant from Telegram: on a message we
resolve/create the owner's session and run the SAME agent path the web chat uses
(``src/agent_loop.stream_agent_loop`` via ``routes.chat_routes``), streaming the
final reply back. Approval-queue items (``src/pending_actions.py``) get inline
Approve/Reject buttons that drive the EXISTING approval path
(``routes.pending_routes.approve_pending`` / ``reject_pending``) — never a side
door around the boundary.

SECURITY: this is an entry point. Only ``TELEGRAM_ALLOWED_USER_ID`` may use it;
every other sender is silently ignored. The bot is DISABLED by default — an
empty ``TELEGRAM_BOT_TOKEN`` (or missing allowed-user id) means no bot is
started. Long-poll only, so NO inbound ingress is required.

Config resolution (env first — Infisical injects env — then settings.json):
  TELEGRAM_BOT_TOKEN        bot token from @BotFather (empty => disabled)
  TELEGRAM_ALLOWED_USER_ID  numeric Telegram user-id of the sole allowed owner
  TELEGRAM_OWNER            app username actions run as (default "jack")
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Callback-data format for inline buttons: "<verb>:<pending_id>". Kept well
# under Telegram's 64-byte callback_data limit (pending ids are 12 hex chars).
APPROVE_PREFIX = "approve:"
REJECT_PREFIX = "reject:"

_DEFAULT_OWNER = "jack"  # fork admin (see CLAUDE.md); override via TELEGRAM_OWNER
_SYSTEM_PROMPT = (
    "You are the user's personal assistant, reached over Telegram. Answer "
    "concisely and use your tools when they help. Mutating actions may be held "
    "for the user's approval."
)


@dataclass(frozen=True)
class TelegramConfig:
    """Resolved bot configuration. ``enabled`` is the single source of truth."""

    token: str
    allowed_user_id: Optional[int]
    app_owner: str

    @property
    def enabled(self) -> bool:
        # Fail-closed: a token with no owner id can't authenticate anyone, so
        # the bot must stay off rather than accept every sender.
        return bool(self.token) and self.allowed_user_id is not None


def _parse_user_id(raw: Any) -> Optional[int]:
    """Parse a Telegram user-id into an int, or None if absent/invalid."""
    if raw is None:
        return None
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def load_config() -> TelegramConfig:
    """Resolve config from env (Infisical) first, then settings.json."""
    def _get(env_key: str, setting_key: str) -> str:
        val = os.getenv(env_key)
        if val is None:
            try:
                from src.settings import get_setting
                val = get_setting(setting_key, "")
            except Exception:
                val = ""
        return (val or "").strip()

    token = _get("TELEGRAM_BOT_TOKEN", "telegram_bot_token")
    allowed = _parse_user_id(_get("TELEGRAM_ALLOWED_USER_ID", "telegram_allowed_user_id"))
    owner = _get("TELEGRAM_OWNER", "telegram_owner") or _DEFAULT_OWNER
    return TelegramConfig(token=token, allowed_user_id=allowed, app_owner=owner)


def is_authorized(config: TelegramConfig, user_id: Optional[int]) -> bool:
    """True only for the single configured owner while the bot is enabled."""
    return config.enabled and user_id is not None and user_id == config.allowed_user_id


def _session_id_for(user_id: int) -> str:
    return f"telegram-{user_id}"


def _extract_delta(event_str: str) -> Optional[str]:
    """Pull visible (non-thinking) text from one SSE line, or None."""
    if not event_str.startswith("data: ") or event_str.startswith("data: [DONE]"):
        return None
    import json
    try:
        data = json.loads(event_str[6:])
    except (ValueError, KeyError):
        return None
    if "delta" in data and not data.get("thinking"):
        return data["delta"]
    return None


async def run_agent_turn(text: str, *, owner: str, session_id: str) -> str:
    """Run one agent turn headlessly and return the aggregated reply text.

    Mirrors ``TaskScheduler._run_agent_loop``: resolve the default endpoint,
    build messages (with session history for continuity when a SessionManager
    is live), stream the agent loop, and collect visible deltas.
    """
    from src.agent_loop import stream_agent_loop
    from src.endpoint_resolver import resolve_endpoint

    url, model, headers = resolve_endpoint("default", owner=owner or None)
    if not url or not model:
        return "No chat model is configured, so I can't answer right now."

    history = _load_history(owner, session_id, text)
    messages = [{"role": "system", "content": _SYSTEM_PROMPT}] + history

    full = ""
    async for event_str in stream_agent_loop(
        endpoint_url=url,
        model=model,
        messages=messages,
        headers=headers or {},
        session_id=session_id,
        owner=owner or None,
    ):
        delta = _extract_delta(event_str)
        if delta:
            full += delta

    full = full.strip()
    _save_reply(session_id, full)
    return full or "(no output)"


def _load_history(owner: str, session_id: str, text: str) -> List[dict]:
    """Append the user turn to the session and return the LLM-ready history.

    Falls back to a stateless single-turn history when no SessionManager is
    running (e.g. tests, or the bot used outside the app process).
    """
    stateless = [{"role": "user", "content": text}]
    try:
        from core.models import ChatMessage, get_session_manager_instance
    except Exception:
        return stateless
    sm = get_session_manager_instance()
    if sm is None:
        return stateless
    try:
        from src.endpoint_resolver import resolve_endpoint
        url, model, _ = resolve_endpoint("default", owner=owner or None)
        sm.ensure_task_session(
            session_id, f"[Telegram] {owner}", url or "", model or "", owner=owner or None
        )
        sm.add_message(session_id, ChatMessage(role="user", content=text))
        sess = sm.get_session(session_id)
        return sess.get_context_messages() if sess else stateless
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("telegram session load failed: %s", e)
        return stateless


def _save_reply(session_id: str, text: str) -> None:
    if not text:
        return
    try:
        from core.models import ChatMessage, get_session_manager_instance
        sm = get_session_manager_instance()
        if sm is not None:
            sm.add_message(session_id, ChatMessage(role="assistant", content=text))
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("telegram reply save failed: %s", e)


# ── Pending-action helpers (pure data; adapters render the keyboard) ──

def build_pending_keyboard(pid: str) -> List[List[Tuple[str, str]]]:
    """Inline-keyboard spec for one pending action: [[(label, callback_data)]]."""
    return [[
        ("✅ Approve", f"{APPROVE_PREFIX}{pid}"),
        ("❌ Reject", f"{REJECT_PREFIX}{pid}"),
    ]]


def pending_items(config: TelegramConfig) -> List[dict]:
    """Owner-scoped list of pending actions (id + summary)."""
    from src import pending_actions as pa
    return pa.list_pending(config.app_owner or None)


def parse_callback(data: Optional[str]) -> Optional[Tuple[str, str]]:
    """Parse inline-button callback data into ("approve"|"reject", pid)."""
    if not data:
        return None
    if data.startswith(APPROVE_PREFIX):
        pid = data[len(APPROVE_PREFIX):].strip()
        return ("approve", pid) if pid else None
    if data.startswith(REJECT_PREFIX):
        pid = data[len(REJECT_PREFIX):].strip()
        return ("reject", pid) if pid else None
    return None


async def handle_callback(config: TelegramConfig, user_id: Optional[int],
                          data: Optional[str]) -> Optional[str]:
    """Route an approve/reject button press through the existing approval path.

    Returns a reply string, or None when the sender is unauthorized (ignored)
    or the callback data is not recognized.
    """
    if not is_authorized(config, user_id):
        logger.warning("telegram: ignoring callback from unauthorized id=%s", user_id)
        return None
    parsed = parse_callback(data)
    if not parsed:
        return None
    verb, pid = parsed
    from routes.pending_routes import approve_pending, reject_pending
    owner = config.app_owner or None
    if verb == "approve":
        res = await approve_pending(pid, owner)
    else:
        res = await reject_pending(pid, owner)
    return _format_decision(verb, pid, res)


def _format_decision(verb: str, pid: str, res: dict) -> str:
    if res.get("error") == "not_found":
        return f"Action {pid} not found (already handled?)."
    if res.get("message") == "already decided":
        return f"Action {pid} was already {res.get('status')}."
    if res.get("error") == "execution_failed":
        return f"Approved {pid} but execution failed: {res.get('detail')}"
    if verb == "approve":
        return f"✅ Approved and ran {res.get('tool_type', pid)}."
    return f"❌ Rejected {pid}."


async def handle_message(config: TelegramConfig, user_id: Optional[int],
                         text: Optional[str]) -> Optional[str]:
    """Route an owner message to the agent and return the reply text.

    Returns None for unauthorized senders (the adapter then stays silent) so no
    information leaks to strangers who probe the bot.
    """
    if not is_authorized(config, user_id):
        logger.warning("telegram: ignoring message from unauthorized id=%s", user_id)
        return None
    body = (text or "").strip()
    if not body:
        return "Send me a message and I'll get to work."
    return await run_agent_turn(
        body, owner=config.app_owner, session_id=_session_id_for(user_id)
    )
