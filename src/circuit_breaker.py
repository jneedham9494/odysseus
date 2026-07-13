"""Per-key circuit breakers for autonomous actions (Phase-4 safety).

A breaker is keyed by ``tool:<tool_type>`` or ``goal:<goal>`` (see :func:`tool_key`
/ :func:`goal_key`). It OPENS (trips) after ``failure_threshold`` failures inside a
rolling ``window_seconds`` window, blocking further autonomous calls on that key.
After ``cooldown_seconds`` it auto-moves to half-open (allows one trial call); a
success closes it, a failure re-opens it. An explicit :func:`reset` closes it now.

Kept separate from :mod:`src.autonomy_guard` so the breaker state machine stays a
small, independently-testable unit. The gate composes both.
"""
from __future__ import annotations

import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, Optional

logger = logging.getLogger(__name__)

# Injectable clock so tests can drive window/cooldown logic deterministically.
_clock: Callable[[], float] = time.time

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_WINDOW_SECONDS = 300.0
DEFAULT_COOLDOWN_SECONDS = 600.0


@dataclass
class BreakerConfig:
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS


@dataclass
class _BreakerState:
    failures: Deque[float] = field(default_factory=deque)
    opened_at: Optional[float] = None


_lock = threading.RLock()
_breakers: Dict[str, _BreakerState] = {}
_config = BreakerConfig()


def configure_breakers(config: BreakerConfig) -> None:
    """Override breaker thresholds (used by app boot / tests)."""
    global _config
    _config = config


def _state(key: str) -> _BreakerState:
    st = _breakers.get(key)
    if st is None:
        st = _BreakerState()
        _breakers[key] = st
    return st


def _prune(st: _BreakerState, now: float) -> None:
    horizon = now - _config.window_seconds
    while st.failures and st.failures[0] < horizon:
        st.failures.popleft()


def record_failure(key: Optional[str]) -> bool:
    """Record a failed autonomous call on ``key``. Returns True if the breaker is
    now open. Reaching the threshold within the rolling window opens it."""
    if not key:
        return False
    now = _clock()
    with _lock:
        st = _state(key)
        _prune(st, now)
        st.failures.append(now)
        if len(st.failures) >= _config.failure_threshold and st.opened_at is None:
            st.opened_at = now
            logger.warning("circuit breaker OPEN for %s (%d failures)", key, len(st.failures))
        return st.opened_at is not None


def record_success(key: Optional[str]) -> None:
    """A successful autonomous call clears the failure window and closes the breaker."""
    if not key:
        return
    with _lock:
        st = _state(key)
        st.failures.clear()
        st.opened_at = None


def is_tripped(key: Optional[str]) -> bool:
    """True if calls on ``key`` are currently blocked. An open breaker auto-moves to
    half-open (returns False, allowing one trial) once the cooldown elapses."""
    if not key:
        return False
    now = _clock()
    with _lock:
        st = _breakers.get(key)
        if st is None or st.opened_at is None:
            return False
        if now - st.opened_at >= _config.cooldown_seconds:
            st.opened_at = None  # half-open: allow a trial call
            _prune(st, now)
            logger.info("circuit breaker half-open (cooldown elapsed) for %s", key)
            return False
        return True


def reset(key: Optional[str]) -> None:
    """Explicitly close a breaker and forget its failures (operator re-enable)."""
    if not key:
        return
    with _lock:
        _breakers.pop(key, None)


def reset_all() -> None:
    with _lock:
        _breakers.clear()


def breaker_status() -> Dict[str, dict]:
    now = _clock()
    with _lock:
        return {
            key: {
                "failures": len(st.failures),
                "tripped": st.opened_at is not None
                and (now - st.opened_at) < _config.cooldown_seconds,
                "opened_at": st.opened_at,
            }
            for key, st in _breakers.items()
        }


def tool_key(tool_type: Optional[str]) -> Optional[str]:
    return f"tool:{tool_type}" if tool_type else None


def goal_key(goal: Optional[str]) -> Optional[str]:
    return f"goal:{goal}" if goal else None
