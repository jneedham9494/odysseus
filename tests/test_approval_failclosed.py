"""The approval gate must fail CLOSED: gate mutators if the policy can't be read."""
import src.agent_loop as agent_loop


def test_fails_closed_on_policy_error(monkeypatch):
    # Simulate confirmation enabled but requires_approval blowing up.
    import src.pending_actions as pa
    monkeypatch.setattr(pa, "requires_approval", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db down")))
    monkeypatch.setattr(pa, "confirm_enabled", lambda: True)
    assert agent_loop._needs_approval("bash", "rm -rf /") is True          # mutator gated
    assert agent_loop._needs_approval("send_email", "...") is True
    assert agent_loop._needs_approval("web_search", "cats") is False       # read not gated


def test_no_gating_when_confirm_disabled(monkeypatch):
    import src.pending_actions as pa
    monkeypatch.setattr(pa, "requires_approval", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(pa, "confirm_enabled", lambda: False)
    # User has gating off → a transient error must not start stalling actions.
    assert agent_loop._needs_approval("bash", "ls") is False


def test_is_mutating_tool_static():
    from src.pending_actions import is_mutating_tool
    assert is_mutating_tool("bash") is True
    assert is_mutating_tool("browser_click") is True
    assert is_mutating_tool("web_search") is False
    assert is_mutating_tool(None) is True  # unknown → safe default
