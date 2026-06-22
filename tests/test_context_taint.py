"""A tainted (web-ingested) session must not auto-fire credentialed actions."""
import src.context_taint as ct


def setup_function():
    ct._TAINTED_SESSIONS.clear()


def test_untrusted_source_classification():
    assert ct.is_untrusted_source("web_fetch")
    assert ct.is_untrusted_source("web_search")
    assert ct.is_untrusted_source("browser_navigate")
    assert not ct.is_untrusted_source("read_file")


def test_credentialed_mutator_classification():
    assert ct.is_credentialed_mutator("send_email")
    assert ct.is_credentialed_mutator("bulk_email")
    assert ct.is_credentialed_mutator("browser_click")
    assert ct.is_credentialed_mutator("api_call", '{"method":"POST","url":"https://x/y"}')
    assert not ct.is_credentialed_mutator("api_call", '{"method":"GET","url":"https://x/y"}')
    assert not ct.is_credentialed_mutator("web_search")  # a read, not an action


def test_taint_then_gate():
    sid = "sess-1"
    # Clean session: a credentialed action is NOT taint-gated.
    assert ct.requires_taint_approval(sid, "send_email") is False
    # Ingest untrusted web content -> session tainted.
    ct.mark_tainted(sid)
    assert ct.is_tainted(sid)
    # Now the same action must be approved.
    assert ct.requires_taint_approval(sid, "send_email") is True
    assert ct.requires_taint_approval(sid, "api_call", '{"method":"DELETE","url":"/x"}') is True
    # Reads stay free even when tainted.
    assert ct.requires_taint_approval(sid, "web_search") is False


def test_other_session_unaffected():
    ct.mark_tainted("a")
    assert ct.requires_taint_approval("b", "send_email") is False


def test_none_session_safe():
    assert ct.is_tainted(None) is False
    ct.mark_tainted(None)  # no-op, no crash
    assert ct.requires_taint_approval(None, "send_email") is False
