"""Graded sensitivity labels layered on top of the binary taint set.

Proves the additive label state (escalate-only) and the connector
source-type classifier, while confirming the existing binary taint semantics
are byte-for-byte preserved.
"""
import src.context_taint as ct


def setup_function():
    ct._TAINTED_SESSIONS.clear()


def test_normalize_sensitivity():
    assert ct.normalize_sensitivity("public") == "public"
    assert ct.normalize_sensitivity("personal") == "personal"
    assert ct.normalize_sensitivity("sensitive") == "sensitive"
    assert ct.normalize_sensitivity("bogus") == ct.DEFAULT_TAINT_SENSITIVITY
    assert ct.normalize_sensitivity(None) == ct.DEFAULT_TAINT_SENSITIVITY


def test_mark_tainted_default_label():
    ct.mark_tainted("s")
    assert ct.is_tainted("s")
    assert ct.session_sensitivity("s") == ct.DEFAULT_TAINT_SENSITIVITY


def test_sensitivity_escalates_never_downgrades():
    ct.mark_tainted("s", ct.SENSITIVITY_PERSONAL)
    assert ct.session_sensitivity("s") == "personal"
    # Escalate up.
    ct.mark_tainted("s", ct.SENSITIVITY_SENSITIVE)
    assert ct.session_sensitivity("s") == "sensitive"
    # A lower label must NOT downgrade.
    ct.mark_tainted("s", ct.SENSITIVITY_PUBLIC)
    assert ct.session_sensitivity("s") == "sensitive"


def test_session_sensitivity_none_when_untainted():
    assert ct.session_sensitivity("nope") is None
    assert ct.session_sensitivity(None) is None


def test_is_untrusted_source_type():
    assert ct.is_untrusted_source_type("connector:miniflux") is True
    assert ct.is_untrusted_source_type("connector:anything") is True
    assert ct.is_untrusted_source_type("personal_doc") is False
    assert ct.is_untrusted_source_type("") is False
    assert ct.is_untrusted_source_type(None) is False


def test_is_untrusted_source_type_distinct_from_tool_classifier():
    # tool_type classifier does not fire on a source_type and vice versa.
    assert ct.is_untrusted_source("connector:miniflux") is False
    assert ct.is_untrusted_source_type("web_fetch") is False


# --- backward-compatibility: existing binary taint behaviour unchanged ---

def test_clear_and_membership_still_work():
    ct.mark_tainted("s")
    assert "s" in ct._TAINTED_SESSIONS      # dict membership == set membership
    ct.clear("s")
    assert ct.is_tainted("s") is False
    assert "s" not in ct._TAINTED_SESSIONS


def test_requires_taint_approval_semantics_preserved():
    sid = "sess-1"
    assert ct.requires_taint_approval(sid, "send_email") is False
    ct.mark_tainted(sid)
    assert ct.requires_taint_approval(sid, "send_email") is True
    assert ct.requires_taint_approval(sid, "web_search") is False


def test_other_session_unaffected():
    ct.mark_tainted("a", ct.SENSITIVITY_SENSITIVE)
    assert ct.requires_taint_approval("b", "send_email") is False
    assert ct.session_sensitivity("b") is None


def test_none_session_safe():
    ct.mark_tainted(None)  # no crash, no-op
    assert ct.is_tainted(None) is False
