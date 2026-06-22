"""Redact high-risk identifiers before text is embedded/stored in the RAG index.

Goal (foundation-phase W2.3 "keep Tier-1 out of RAG context"): even if sensitive
content reaches the vector store, raw secrets and financial/government identifiers
should not be embedded or kept as retrievable plaintext — you can't leak via RAG
what was never indexed.

Deliberately conservative: targets secrets (API keys, tokens, private keys) and
hard identifiers (card numbers, IBAN, SSN) — NOT names/emails/phones, which are
often legitimately useful for retrieval. Callers can opt out per-document with
metadata ``{"redact": False}`` (e.g. a vetted, non-sensitive corpus).
"""
from __future__ import annotations

import re
from typing import Tuple

_PATTERNS: list[tuple[re.Pattern, str]] = [
    # PEM private key blocks
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.DOTALL), "[REDACTED:PRIVATE_KEY]"),
    # JWTs
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
     "[REDACTED:JWT]"),
    # Common provider API keys / tokens
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "[REDACTED:API_KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:AWS_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "[REDACTED:GOOGLE_KEY]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED:GITHUB_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED:SLACK_TOKEN]"),
    # key/secret/token/password = value
    (re.compile(r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*"
                r"['\"]?[A-Za-z0-9_\-\.]{8,}['\"]?"), "[REDACTED:SECRET]"),
    # IBAN
    (re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"), "[REDACTED:IBAN]"),
    # US SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED:SSN]"),
]

# Payment-card numbers: 13–19 digits with optional space/dash grouping, validated
# by Luhn to cut false positives (order numbers, ids).
_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")


def _luhn_ok(digits: str) -> bool:
    s, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        s += d
        alt = not alt
    return s % 10 == 0


def _redact_cards(text: str) -> Tuple[str, int]:
    hits = 0

    def repl(m: re.Match) -> str:
        nonlocal hits
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            hits += 1
            return "[REDACTED:CARD]"
        return m.group(0)

    return _CARD_RE.sub(repl, text), hits


def redact_for_index(text: str) -> Tuple[str, int]:
    """Return (redacted_text, num_redactions). Safe on any input."""
    if not text or not isinstance(text, str):
        return text, 0
    count = 0
    for pat, repl in _PATTERNS:
        text, n = pat.subn(repl, text)
        count += n
    text, n = _redact_cards(text)
    count += n
    return text, count
