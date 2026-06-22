"""Agent subprocesses must never receive app secrets via their environment."""
import pytest

from src.sandbox_env import build_agent_subproc_env

_SECRETY = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASS", "CREDENTIAL")


def test_no_app_secrets_leak(monkeypatch):
    for k in (
        "OPENAI_API_KEY", "GOOGLE_API_KEY", "HF_TOKEN", "TAVILY_API_KEY",
        "SERPER_API_KEY", "BRAVE_API_KEY", "EMBEDDING_API_KEY",
        "ODYSSEUS_ADMIN_PASSWORD", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD",
    ):
        monkeypatch.setenv(k, "SHOULD-NOT-LEAK")
    env = build_agent_subproc_env("/tmp/work")
    leaked = [k for k in env if any(tok in k.upper() for tok in _SECRETY)]
    assert not leaked, f"secret-like vars leaked to agent subprocess: {leaked}"
    for k in ("OPENAI_API_KEY", "GOOGLE_API_KEY", "HF_TOKEN", "ODYSSEUS_ADMIN_PASSWORD"):
        assert k not in env


def test_essentials_present(monkeypatch):
    monkeypatch.setenv("PATH", "/custom/bin:/usr/bin")
    env = build_agent_subproc_env("/tmp/work")
    assert env["PATH"] == "/custom/bin:/usr/bin"   # real PATH preserved
    assert env["HOME"] == "/tmp/work"
    assert env["TERM"] and env["PYTHONUNBUFFERED"] == "1"


def test_path_defaulted_when_absent(monkeypatch):
    monkeypatch.delenv("PATH", raising=False)
    assert "/usr/bin" in build_agent_subproc_env("/tmp/work")["PATH"]


def test_extra_overrides(monkeypatch):
    env = build_agent_subproc_env("/tmp/work", extra={"FOO": "bar"})
    assert env["FOO"] == "bar"
