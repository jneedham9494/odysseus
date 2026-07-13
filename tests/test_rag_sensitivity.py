"""Tests for src.rag_sensitivity (MR-9 SD-RAG sensitivity + redaction hardening).

Covers: planted secrets masked before embedding, correct graded labels, the
fail-closed guarantee (never downgraded on ambiguity), and a bypass attempt via
a crafted/mislabelled input that must neither leak the secret nor suppress the
true label.
"""
from __future__ import annotations

import pytest

from src.rag_sensitivity import (
    Sensitivity,
    classify,
    classify_and_redact,
    encrypt_raw_for_storage,
    harden_redact,
)

# Planted secrets (fake but format-valid). Card + IBAN are Luhn/format valid.
API_KEY = "sk-ABCDEFGHIJKLMNOPQRSTUVWX0123"
IBAN = "GB82WEST12345698765432"
SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"  # Luhn-valid Visa test number
HEALTH = "Patient was diagnosed with cancer and started chemotherapy."


# --- Planted secrets are masked before embedding --------------------------------

@pytest.mark.parametrize(
    "secret,marker",
    [
        (API_KEY, "sk-"),
        (IBAN, "WEST"),
        (SSN, "45-6789"),
        (CARD, "4111"),
    ],
)
def test_classify_and_redact_masks_planted_identifiers(secret: str, marker: str):
    text = f"here is the value {secret} keep it safe"
    redacted, _label = classify_and_redact(text)
    assert marker not in redacted
    assert "[REDACTED:" in redacted


def test_classify_and_redact_masks_health_terms():
    redacted, label = classify_and_redact(HEALTH)
    assert "cancer" not in redacted.lower()
    assert "chemotherapy" not in redacted.lower()
    assert "[REDACTED:HEALTH]" in redacted
    assert label == "tier1-financial-health-id"


def test_harden_redact_extends_base_and_masks_icd10():
    text = f"secret={API_KEY} dx code E11.9 for the patient"
    redacted, count = harden_redact(text)
    assert API_KEY not in redacted  # base redaction still applied (additive)
    assert "E11.9" not in redacted  # hardening layer adds ICD-10 masking
    assert "[REDACTED:HEALTH_CODE]" in redacted
    assert count >= 2


# --- Labels assigned correctly --------------------------------------------------

def test_public_text_is_public():
    assert classify("The weather is pleasant this afternoon.") is Sensitivity.PUBLIC


def test_email_is_personal():
    assert classify("ping me at bob@example.com later") is Sensitivity.PERSONAL


def test_phone_is_personal():
    assert classify("call +1 415 555 0132 tomorrow") is Sensitivity.PERSONAL


def test_api_key_is_sensitive():
    assert classify(f"token: {API_KEY}") is Sensitivity.SENSITIVE


@pytest.mark.parametrize("payload", [IBAN, SSN, CARD, HEALTH])
def test_financial_health_id_is_tier1(payload: str):
    assert classify(f"record: {payload}") is Sensitivity.TIER1


def test_label_strings_match_taxonomy():
    assert Sensitivity.TIER1.label == "tier1-financial-health-id"
    assert Sensitivity.PUBLIC.label == "public"


# --- Fail-closed: never downgraded on ambiguity ---------------------------------

def test_declared_public_but_ssn_present_upgrades_to_tier1():
    label = classify(f"nothing to see {SSN}", declared_sensitivity="public")
    assert label is Sensitivity.TIER1


def test_declared_higher_than_detected_is_not_downgraded():
    # Content looks public, but the caller declared tier1 -> stays tier1.
    label = classify("just a friendly note", declared_sensitivity="tier1")
    assert label is Sensitivity.TIER1


def test_unknown_declared_label_does_not_downgrade():
    # Garbage declared value must not lower a detected tier.
    label = classify(f"key {API_KEY}", declared_sensitivity="totally-safe-promise")
    assert label is Sensitivity.SENSITIVE


def test_declared_floor_honored_when_no_signal():
    assert classify("plain text", declared_sensitivity="sensitive") is Sensitivity.SENSITIVE


def test_non_string_input_returns_declared_floor():
    assert classify(None, declared_sensitivity="personal") is Sensitivity.PERSONAL  # type: ignore[arg-type]
    assert classify(None) is Sensitivity.PUBLIC  # type: ignore[arg-type]


# --- Bypass attempt does not leak -----------------------------------------------

def test_bypass_mislabelled_public_secret_is_masked_and_relabelled():
    """Caller declares 'public' while planting a secret + card: must mask both and
    report the true (highest) label, so the write-path cannot be tricked."""
    crafted = f"totally public content {API_KEY} and my card {CARD}"
    redacted, label = classify_and_redact(crafted, declared_sensitivity="public")
    assert API_KEY not in redacted
    assert "4111" not in redacted
    assert label == "tier1-financial-health-id"  # not downgraded to declared 'public'


def test_bypass_empty_and_garbage_declared_are_safe():
    redacted, label = classify_and_redact(f"{SSN}", declared_sensitivity="")
    assert SSN not in redacted
    assert label == "tier1-financial-health-id"


# --- Encrypted-raw storage seam is a documented, non-leaking stub ---------------

def test_encrypt_raw_for_storage_is_documented_seam():
    with pytest.raises(NotImplementedError):
        encrypt_raw_for_storage("secret original", "tier1-financial-health-id")
