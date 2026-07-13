"""Graded sensitivity classification + redaction hardening for the RAG write-path.

STANDALONE, additive module (MR-9 SD-RAG sensitivity + redaction hardening).

It does NOT rewrite :mod:`src.rag_redaction`; it *calls* ``redact_for_index`` and
layers extra coverage on top (health / medical identifiers), then assigns a graded
sensitivity label. This keeps the base connector redaction intact and conflict-free.

Taxonomy (ordered, low -> high)::

    public        no detected identifiers / freely shareable
    personal      ordinary PII (email, phone)
    sensitive     credentials / secrets (API keys, tokens, private keys)
    tier1-...     regulated: financial (card, IBAN), health, government id (SSN)

Fail-closed guarantee: the returned label is the *maximum* of the declared label
and every signal detected in the raw text. Sensitivity is NEVER downgraded on
ambiguity — an unknown/garbage ``declared_sensitivity`` cannot lower the result,
and a lower declared label cannot override a higher detected one.

Write-path contract::

    redacted_text, label = classify_and_redact(text, declared_sensitivity)
    # embed/store redacted_text; persist label as metadata

Redacted-for-embedding is implemented now. Encrypted-raw storage is left as a
documented seam (:func:`encrypt_raw_for_storage`).

Future upgrade: swap the rule-based detectors for Microsoft Presidio (NER-backed
recognizers). Presidio is intentionally NOT a hard dependency here — this module
stays on stdlib + the existing rule-based redaction so it can run offline in the
embedding hot-path without model downloads.
"""
from __future__ import annotations

import re
from enum import IntEnum
from typing import Optional, Tuple

from src.rag_redaction import _luhn_ok, redact_for_index

__all__ = [
    "Sensitivity",
    "classify_and_redact",
    "classify",
    "harden_redact",
    "encrypt_raw_for_storage",
]


class Sensitivity(IntEnum):
    """Ordered sensitivity tiers. Higher value == more sensitive == fail-closed."""

    PUBLIC = 0
    PERSONAL = 1
    SENSITIVE = 2
    TIER1 = 3

    @property
    def label(self) -> str:
        return _LABELS[self]


_LABELS: dict[Sensitivity, str] = {
    Sensitivity.PUBLIC: "public",
    Sensitivity.PERSONAL: "personal",
    Sensitivity.SENSITIVE: "sensitive",
    Sensitivity.TIER1: "tier1-financial-health-id",
}

# Reverse map for parsing a declared label.
_BY_LABEL: dict[str, Sensitivity] = {v: k for k, v in _LABELS.items()}


def _parse_declared(declared: Optional[str]) -> Sensitivity:
    """Parse a declared label into a floor tier.

    Fail-closed: a value we cannot recognise is treated as PUBLIC (floor 0) so it
    can never *downgrade* the detected result, but a recognised higher tier is
    honoured as a lower bound (never downgraded below what the caller declared).
    """
    if not declared or not isinstance(declared, str):
        return Sensitivity.PUBLIC
    norm = declared.strip().lower()
    if norm in _BY_LABEL:
        return _BY_LABEL[norm]
    if norm.startswith("tier1") or norm.startswith("tier-1"):
        return Sensitivity.TIER1
    if norm in ("secret", "credential", "credentials"):
        return Sensitivity.SENSITIVE
    if norm in ("pii", "personal-data"):
        return Sensitivity.PERSONAL
    if norm == "public":
        return Sensitivity.PUBLIC
    # Unknown / crafted value: do not trust it to lower sensitivity.
    return Sensitivity.PUBLIC


# --- Detection signals (run on RAW text, before redaction, for classification) --

# Tier-1: regulated financial / government identifiers.
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_CARD_RE = re.compile(r"\b(?:\d[ -]?){12,18}\d\b")

# Sensitive: credentials / secrets.
_SECRET_RES: tuple[re.Pattern, ...] = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(
        r"(?i)\b(api[_-]?key|secret|token|password|passwd|bearer)\b\s*[:=]\s*"
        r"['\"]?[A-Za-z0-9_\-\.]{8,}['\"]?"
    ),
)

# Personal: ordinary PII (kept in the index for retrieval, but bumps the label).
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?\d[\d ().-]{7,}\d)(?!\d)")

# Health / medical identifiers — the hardening layer this module ADDS on top of
# the base redaction (which deliberately skips health terms). Curated, conservative
# list of regulated-health signals; matched terms are masked and flag Tier-1.
_HEALTH_TERMS: tuple[str, ...] = (
    "hiv", "aids", "cancer", "carcinoma", "tumou?r", "diabet(?:es|ic)",
    "depression", "bipolar", "schizophreni[ac]", "hepatitis", "diagnos(?:is|ed|es)",
    "prescription", "prescribed", "chemotherapy", "psychiatric", "mental health",
    "pregnan(?:t|cy)", "miscarriage", "abortion", "immunocompromised",
    "disability", "medicare", "medicaid", "medical record",
)
_HEALTH_RE = re.compile(r"(?i)\b(?:" + "|".join(_HEALTH_TERMS) + r")\b")
# ICD-10 diagnosis codes (e.g. E11.9, C50.912): letter + 2 digits + a decimal
# subcode. The decimal is REQUIRED: the bare 3-char category form (letter + 2
# digits) is indistinguishable from ordinary alphanumeric tokens (part numbers,
# order codes, "B12", "A15") and caused heavy false positives. Requiring the
# ".subcode" keeps real diagnosis codes while cutting that noise now that this
# runs on the live write-path.
_ICD10_RE = re.compile(r"\b[A-TV-Z]\d{2}\.[A-Z0-9]{1,4}\b")


def _has_card(text: str) -> bool:
    """True if any Luhn-valid 13-19 digit card number is present."""
    for m in _CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            return True
    return False


def _detect(text: str) -> Sensitivity:
    """Highest sensitivity tier evidenced by the raw text. PUBLIC if none."""
    # Tier-1 first (short-circuit at the top).
    if (
        _has_card(text)
        or _IBAN_RE.search(text)
        or _SSN_RE.search(text)
        or _HEALTH_RE.search(text)
        or _ICD10_RE.search(text)
    ):
        return Sensitivity.TIER1
    if any(rx.search(text) for rx in _SECRET_RES):
        return Sensitivity.SENSITIVE
    if _EMAIL_RE.search(text) or _PHONE_RE.search(text):
        return Sensitivity.PERSONAL
    return Sensitivity.PUBLIC


def classify(text: str, declared_sensitivity: Optional[str] = None) -> Sensitivity:
    """Return the fail-closed sensitivity tier for ``text``.

    Result = max(declared floor, detected tier). Never downgraded on ambiguity.
    Safe on any input (non-str / empty -> the declared floor, min PUBLIC).
    """
    floor = _parse_declared(declared_sensitivity)
    if not text or not isinstance(text, str):
        return floor
    return Sensitivity(max(int(floor), int(_detect(text))))


def harden_redact(text: str) -> Tuple[str, int]:
    """Base redaction (:func:`redact_for_index`) PLUS health/medical hardening.

    Additive: calls the existing connector redaction unchanged, then masks health
    terms and ICD-10 codes it intentionally leaves alone. Returns
    ``(redacted_text, num_redactions)``. Safe on any input.
    """
    if not text or not isinstance(text, str):
        return text, 0
    redacted, count = redact_for_index(text)
    redacted, n = _HEALTH_RE.subn("[REDACTED:HEALTH]", redacted)
    count += n
    redacted, n = _ICD10_RE.subn("[REDACTED:HEALTH_CODE]", redacted)
    count += n
    return redacted, count


def classify_and_redact(
    text: str, declared_sensitivity: Optional[str] = None
) -> Tuple[str, str]:
    """Single entry point for the RAG write-path.

    Classifies ``text`` (fail-closed against ``declared_sensitivity``) using the
    RAW text, then returns the redacted-for-embedding text and the string label.

    Classification runs on the raw text and redaction is ALWAYS applied, so a
    caller that mislabels sensitive content (e.g. declares "public" while planting
    an API key or SSN) can neither embed the secret nor suppress the true label.

    Returns ``(redacted_text, sensitivity_label)``.
    """
    label = classify(text, declared_sensitivity).label
    redacted, _ = harden_redact(text)
    return redacted, label


def encrypt_raw_for_storage(text: str, label: str) -> bytes:
    """SEAM: encrypted-raw storage of the *unredacted* original.

    Not implemented in this MR. The redacted-for-embedding path (above) is the
    only one wired into the write-path today. When encrypted raw retention is
    added, this should envelope-encrypt ``text`` under a per-tenant/tier key
    (e.g. AES-256-GCM with a KMS-wrapped DEK), tagging the ciphertext with
    ``label`` so retrieval can enforce tier-based access. Kept as an explicit,
    documented boundary so the write-path can adopt it without reshaping callers.

    Raises:
        NotImplementedError: always, until encrypted-raw storage lands.
    """
    raise NotImplementedError(
        "encrypted-raw storage is a documented seam; only the "
        "redacted-for-embedding path is implemented in MR-9"
    )
