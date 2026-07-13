"""WatermarkStore: schema, per-owner isolation, monotonic advance."""
import os

from src.connectors.state import WatermarkStore, _cursor_is_greater


def _store(tmp_path) -> WatermarkStore:
    return WatermarkStore(db_path=os.path.join(str(tmp_path), "connector_state.db"))


def test_get_cursor_none_on_first_sync(tmp_path):
    store = _store(tmp_path)
    assert store.get_cursor("miniflux", "jack") is None


def test_advance_then_get_roundtrip(tmp_path):
    store = _store(tmp_path)
    assert store.advance("miniflux", "jack", "42") is True
    assert store.get_cursor("miniflux", "jack") == "42"


def test_advance_is_monotonic_for_int_cursors(tmp_path):
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "100")
    # A stale/lower cursor must NOT overwrite.
    assert store.advance("miniflux", "jack", "50") is False
    assert store.get_cursor("miniflux", "jack") == "100"
    # A strictly greater cursor advances.
    assert store.advance("miniflux", "jack", "150") is True
    assert store.get_cursor("miniflux", "jack") == "150"


def test_equal_cursor_not_rewritten(tmp_path):
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "7")
    assert store.advance("miniflux", "jack", "7") is False


def test_per_owner_isolation(tmp_path):
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "10")
    store.advance("miniflux", "alice", "99")
    assert store.get_cursor("miniflux", "jack") == "10"
    assert store.get_cursor("miniflux", "alice") == "99"
    # Advancing one owner never touches the other.
    store.advance("miniflux", "jack", "20")
    assert store.get_cursor("miniflux", "jack") == "20"
    assert store.get_cursor("miniflux", "alice") == "99"


def test_per_connector_isolation(tmp_path):
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "10")
    store.advance("gitea", "jack", "500")
    assert store.get_cursor("miniflux", "jack") == "10"
    assert store.get_cursor("gitea", "jack") == "500"


def test_reset_clears_row(tmp_path):
    store = _store(tmp_path)
    store.advance("miniflux", "jack", "10")
    store.reset("miniflux", "jack")
    assert store.get_cursor("miniflux", "jack") is None


def test_empty_owner_or_connector_is_noop(tmp_path):
    store = _store(tmp_path)
    assert store.advance("miniflux", "", "10") is False
    assert store.advance("", "jack", "10") is False
    assert store.get_cursor("", "jack") is None


def test_cursor_greater_helper():
    assert _cursor_is_greater("5", None) is True
    assert _cursor_is_greater("5", "4") is True
    assert _cursor_is_greater("4", "5") is False
    # Non-int cursors fall back to lexical comparison.
    assert _cursor_is_greater("b", "a") is True
    assert _cursor_is_greater("a", "b") is False
