"""Regression tests for the configurable LLM connect timeout.

Background: chat uses the streaming path, which (unlike llm_call) does not retry
a connect error -- it marks the host and emits a 503 immediately. With the old
hard-coded connect=3.0s, a brief blip on the first (cold) connect of an idle
chat to an offshore/public endpoint surfaced as an intermittent 503 that cleared
on resend. The connect budget is now LLMConfig.CONNECT_TIMEOUT (env
LLM_CONNECT_TIMEOUT), applied via _call_timeout/_stream_timeout helpers.
"""
import importlib
import importlib.util
import httpx
import pytest

from src import llm_core
from src.llm_core import LLMConfig, _call_timeout, _stream_timeout


def test_default_connect_timeout_is_widened_not_three():
    # Regression guard: must not regress to the old too-tight 3.0s default.
    assert LLMConfig.CONNECT_TIMEOUT >= 8.0
    assert LLMConfig.CONNECT_TIMEOUT != 3.0
    assert LLMConfig.CONNECT_TIMEOUT == 10.0


def test_call_timeout_uses_config_connect_and_passes_read():
    t = _call_timeout(45)
    assert isinstance(t, httpx.Timeout)
    assert t.connect == LLMConfig.CONNECT_TIMEOUT
    assert t.read == 45.0
    assert t.write == 10.0
    assert t.pool == 5.0


def test_stream_timeout_uses_config_connect_and_passes_read():
    t = _stream_timeout(300)
    assert isinstance(t, httpx.Timeout)
    assert t.connect == LLMConfig.CONNECT_TIMEOUT
    assert t.read == 300.0
    assert t.write == 30.0
    assert t.pool == 5.0


def test_helpers_are_config_driven(monkeypatch):
    # Helpers read LLMConfig at call time, so ops can tune without code edits.
    monkeypatch.setattr(LLMConfig, "CONNECT_TIMEOUT", 4.5)
    assert _call_timeout(30).connect == 4.5
    assert _stream_timeout(30).connect == 4.5


def test_env_override_is_honoured(monkeypatch):
    """LLM_CONNECT_TIMEOUT is read at import time, so re-execute the module.

    Into a THROWAWAY module object, not over the live one. `importlib.reload`
    re-runs the file into the real module's __dict__, which rebinds every
    module-level singleton - including caches such as `_kimi_code_ua_cache`.
    Tests that imported one of those names before the reload keep the old
    object while the functions read the new one, so what they assert depends on
    which file pytest collected first (issue #41 - test_kimi_code_user_agent).
    A private copy under its own name has no such reach: nothing else can see
    it, and sys.modules is untouched.
    """
    monkeypatch.setenv("LLM_CONNECT_TIMEOUT", "6.5")

    spec = importlib.util.spec_from_file_location(
        "_llm_core_env_override_probe", llm_core.__file__
    )
    probe = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(probe)

    assert probe.LLMConfig.CONNECT_TIMEOUT == 6.5
    # The live module keeps the default it was imported with.
    assert llm_core.LLMConfig.CONNECT_TIMEOUT == 10.0
