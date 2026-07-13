"""ntfy Actions spine: categorized push with one-tap http-action buttons.

ntfy renders an ``Actions`` header as tappable buttons on the phone. This module
turns a queued agent action (``src/pending_actions.py``) into a categorized
notification carrying **Approve** / **Reject** http-action buttons wired at the
approval-queue routes (``routes/pending_routes.py``), so the operator can decide
from the lock screen without opening the app. The same primitives back the
future kill-switch surface.

Authorization without a cookie: each button URL carries a per-``(id, action)``
HMAC token. The raw signing secret (the in-process internal-tool token) never
leaves the box -- only a scoped signature travels, so a leaked notification can
approve **that one** action and nothing else. Tokens are verified in constant
time at the route.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from typing import Dict, Tuple

# Actions the token/URL builders will emit. Anything else is rejected so a
# caller can't mint a signature for an unexpected verb.
ALLOWED_ACTIONS = ("approve", "reject", "kill")

# A pending id is uuid4().hex[:12]; keep the guard loose but bounded.
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# Tool -> ntfy category. Priority "urgent" buzzes hardest. Categorization is
# best-effort UI sugar; unknown tools fall back to _DEFAULT_CATEGORY.
_DESTRUCTIVE = {
    "bash", "python", "delete_file", "move_file",
    "write_file", "edit_file",
}
_MESSAGING = {"send_email", "reply_to_email", "bulk_email"}
_DEFAULT_CATEGORY: Tuple[str, str] = ("high", "warning")


def _signing_key() -> bytes:
    """HMAC key derived from the per-process internal-tool token.

    Imported lazily so this module carries no import-time dependency on the
    FastAPI middleware (keeps it cheap to unit-test in isolation)."""
    from core.middleware import INTERNAL_TOOL_TOKEN

    return hashlib.sha256(
        f"ntfy-action:{INTERNAL_TOOL_TOKEN}".encode("utf-8")
    ).digest()


def _validate_pid(pid: str) -> str:
    if not isinstance(pid, str) or not _ID_RE.match(pid):
        raise ValueError(f"invalid pending id: {pid!r}")
    return pid


def _validate_action(action: str) -> str:
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"unsupported action: {action!r}")
    return action


def make_action_token(pid: str, action: str) -> str:
    """Return an HMAC-SHA256 hex signature scoped to exactly this id + action."""
    _validate_pid(pid)
    _validate_action(action)
    msg = f"{pid}:{action}".encode("utf-8")
    return hmac.new(_signing_key(), msg, hashlib.sha256).hexdigest()


def verify_action_token(pid: str, action: str, token: str) -> bool:
    """Constant-time check that ``token`` authorizes ``action`` on ``pid``.

    Any malformed input (bad id, unknown action, non-string token) is a
    verification failure rather than an exception, so route code can treat this
    as a plain boolean gate."""
    if not isinstance(token, str) or not token:
        return False
    try:
        expected = make_action_token(pid, action)
    except ValueError:
        return False
    return hmac.compare_digest(expected, token)


def categorize(tool_type: str) -> Tuple[str, str]:
    """Map a tool type to an ntfy (priority, tags) pair for the push."""
    if tool_type in _DESTRUCTIVE:
        return ("urgent", "warning,skull")
    if tool_type in _MESSAGING:
        return ("high", "email")
    return _DEFAULT_CATEGORY


def approval_url(base_url: str, pid: str, action: str) -> str:
    """Full, token-authorized URL for an approval-queue http-action button."""
    _validate_action(action)
    base = (base_url or "").rstrip("/")
    if not base:
        raise ValueError("base_url is required to build an action URL")
    token = make_action_token(pid, action)
    return f"{base}/api/pending-actions/{pid}/{action}?token={token}"


def _http_action(label: str, url: str) -> str:
    # ntfy splits actions on ';' and fields on ','. Labels must stay comma-free;
    # clear=true dismisses the notification after the tap.
    if "," in label or ";" in label:
        raise ValueError(f"action label must not contain ',' or ';': {label!r}")
    return f"http, {label}, {url}, method=POST, clear=true"


def build_approval_headers(pid: str, tool_type: str, base_url: str) -> Dict[str, str]:
    """Build ntfy headers for a pending action with Approve/Reject buttons.

    Requires ``base_url`` (the app's public origin) so the buttons can reach the
    approval routes. Raises ``ValueError`` if it is missing/blank."""
    _validate_pid(pid)
    base = (base_url or "").rstrip("/")
    if not base:
        raise ValueError("base_url is required to build approval actions")
    priority, tags = categorize(tool_type)
    actions = "; ".join([
        _http_action("Approve", approval_url(base, pid, "approve")),
        _http_action("Reject", approval_url(base, pid, "reject")),
        f"view, Open, {base}/?pending={pid}",
    ])
    return {
        "Title": "Assistant action needs approval",
        "Priority": priority,
        "Tags": tags,
        "Actions": actions,
    }


def build_kill_switch_headers(base_url: str, path: str = "/api/kill-switch") -> Dict[str, str]:
    """Build a panic push with a single one-tap kill-switch button.

    Future surface: emits the categorized notification + token-signed action so
    the operator can halt the agent from the phone once a kill route lands at
    ``path``. Reuses the same signing spine as approvals."""
    base = (base_url or "").rstrip("/")
    if not base:
        raise ValueError("base_url is required to build a kill-switch action")
    token = make_action_token("global", "kill")
    url = f"{base}{path}?token={token}"
    return {
        "Title": "Kill switch",
        "Priority": "urgent",
        "Tags": "rotating_light,skull",
        "Actions": _http_action("STOP agent", url),
    }
