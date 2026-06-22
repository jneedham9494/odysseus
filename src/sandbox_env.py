"""Minimal, secret-free environment for agent-controlled subprocesses.

The bash / python / background-job tools run code the *agent* chooses — and a
prompt injection can choose it too. They must NOT inherit the app's process
environment, which holds API keys, tokens and passwords (OPENAI_API_KEY,
GOOGLE_API_KEY, BRAVE/TAVILY/SERPER keys, HF_TOKEN, ODYSSEUS_ADMIN_PASSWORD,
DB creds, ...). We build their environment from a small allowlist instead of
copying os.environ, so `env` (bash) or os.environ (python) in agent-run code
reveals nothing sensitive — closing the simplest exfiltration path.
"""
from __future__ import annotations

import os

# Non-secret, behaviour-relevant variables worth passing through when present.
_SAFE_PASSTHROUGH = (
    "PATH", "TZ", "SHELL", "USER", "LOGNAME",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME",
    "LC_COLLATE", "LC_MONETARY", "LC_MESSAGES", "LC_PAPER",
    # Non-secret Windows essentials so the cmd.exe code path keeps working.
    "SYSTEMROOT", "COMSPEC", "PATHEXT", "TEMP", "TMP", "WINDIR",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
)
_DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"


def build_agent_subproc_env(workdir: str, extra: dict | None = None) -> dict:
    """Return a minimal environment for agent subprocesses — NO app secrets.

    Starts from an allowlist (never os.environ), so credentials present in the
    parent process are not handed to agent-controlled code. `extra` may add
    explicitly-vetted, non-secret values (e.g. a tool that legitimately needs
    a specific variable).
    """
    env = {k: os.environ[k] for k in _SAFE_PASSTHROUGH if os.environ.get(k)}
    env.setdefault("PATH", _DEFAULT_PATH)
    env.update({
        "HOME": workdir,
        "TERM": "xterm-256color",
        "COLUMNS": "120",
        "LINES": "40",
        "PYTHONUNBUFFERED": "1",
    })
    if extra:
        env.update(extra)
    return env
