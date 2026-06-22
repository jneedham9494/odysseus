"""High-risk secrets/identifiers must be redacted before RAG indexing."""
from src.rag_redaction import redact_for_index


def test_secrets_and_ids_redacted():
    raw = (
        "key sk-abcdefABCDEF0123456789xyz and AKIAIOSFODNN7EXAMPLE and "
        "token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ; "
        "api_key = supersecretvalue123 ; SSN 123-45-6789 ; "
        "card 4111 1111 1111 1111 ; iban GB82WEST12345698765432"
    )
    out, n = redact_for_index(raw)
    for token in ("sk-abcdef", "AKIAIOSFODNN7EXAMPLE", "ghp_ABCDEF",
                  "supersecretvalue123", "123-45-6789", "4111 1111 1111 1111",
                  "GB82WEST12345698765432"):
        assert token not in out, f"leaked: {token}"
    assert n >= 6
    assert "[REDACTED:" in out


def test_benign_text_untouched():
    raw = "Meeting notes: discuss the Q3 roadmap with Alice. Order #100200300400."
    out, n = redact_for_index(raw)
    # An invalid (non-Luhn) long number must NOT be flagged as a card.
    assert out == raw
    assert n == 0


def test_safe_on_empty():
    assert redact_for_index("") == ("", 0)
    assert redact_for_index(None) == (None, 0)
