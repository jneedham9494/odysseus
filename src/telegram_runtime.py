"""aiogram long-poll runtime for the Telegram bridge.

Kept separate from ``src/telegram_bot.py`` so the pure, testable bot logic never
depends on aiogram. This module holds the thin aiogram adapters (dispatcher
wiring + the start hook). aiogram is imported lazily so importing this module
does not require the optional dependency.

The bot is DISABLED by default: ``start_telegram_bot`` returns None unless a
token AND an allowed-user id are configured, so app startup can call it
unconditionally and get a no-op when unconfigured.
"""
from __future__ import annotations

import logging
from typing import Optional

from src.telegram_bot import (
    TelegramConfig,
    build_pending_keyboard,
    handle_callback,
    handle_message,
    is_authorized,
    load_config,
    pending_items,
)

logger = logging.getLogger(__name__)


def build_dispatcher(config: TelegramConfig):
    """Build an aiogram Dispatcher with the message + callback handlers wired."""
    from aiogram import Dispatcher, F
    from aiogram.types import (
        CallbackQuery,
        InlineKeyboardButton,
        InlineKeyboardMarkup,
        Message,
    )

    dp = Dispatcher()

    def _markup(pid: str) -> InlineKeyboardMarkup:
        rows = [
            [InlineKeyboardButton(text=label, callback_data=cb) for label, cb in row]
            for row in build_pending_keyboard(pid)
        ]
        return InlineKeyboardMarkup(inline_keyboard=rows)

    @dp.message(F.text.startswith("/pending"))
    async def _on_pending(message: Message) -> None:
        if not is_authorized(config, getattr(message.from_user, "id", None)):
            return
        items = pending_items(config)
        if not items:
            await message.answer("No pending actions.")
            return
        for item in items:
            await message.answer(
                f"⏳ {item.get('summary') or item.get('id')}",
                reply_markup=_markup(item["id"]),
            )

    @dp.message()
    async def _on_message(message: Message) -> None:
        reply = await handle_message(
            config, getattr(message.from_user, "id", None), message.text
        )
        if reply is not None:
            await message.answer(reply)

    @dp.callback_query()
    async def _on_callback(callback: CallbackQuery) -> None:
        reply = await handle_callback(
            config, getattr(callback.from_user, "id", None), callback.data
        )
        await callback.answer()
        if reply is not None and callback.message is not None:
            await callback.message.answer(reply)

    return dp


async def _run_polling(config: TelegramConfig) -> None:
    from aiogram import Bot
    bot = Bot(token=config.token)
    dp = build_dispatcher(config)
    logger.info("telegram bot: starting long-poll for owner id=%s", config.allowed_user_id)
    try:
        await dp.start_polling(bot)
    finally:
        await bot.session.close()


def start_telegram_bot(config: Optional[TelegramConfig] = None):
    """Start hook: return an asyncio Task running the bot, or None if disabled.

    Safe to call from app startup — it NEVER starts a live bot unless a token
    (and allowed-user id) are configured. Returns None when disabled so callers
    can no-op cleanly.
    """
    import asyncio
    config = config or load_config()
    if not config.enabled:
        logger.info("telegram bot disabled (no token / owner id configured)")
        return None
    try:
        import aiogram  # noqa: F401
    except ImportError:
        logger.warning("telegram bot configured but aiogram is not installed; skipping")
        return None
    return asyncio.create_task(_run_polling(config))
