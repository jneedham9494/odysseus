"""Actuator tiering (MR-16).

Every actuator is classified read / draft / write-gated / hitl-forever by
``tool_security.actuator_tier``. Reads and drafts run autonomously; writes gate
behind the approval queue when the operator turns it on; money / people /
deletion / physical are hitl-forever and gate regardless of any setting; unknown
tools fail closed (gated).
"""
from __future__ import annotations

import json

import pytest

import src.pending_actions as pa
from src.tool_security import (
    TIER_DRAFT,
    TIER_HITL,
    TIER_READ,
    TIER_WRITE,
    actuator_tier,
)


def _api(method: str, path: str = "/api/x") -> str:
    return json.dumps({"method": method, "path": path})


# --- tier classification (pure, no settings) -------------------------------

@pytest.mark.parametrize("tool", ["read_file", "grep", "ls", "web_search", "list_emails"])
def test_actuator_tier_read_tools_are_read(tool):
    assert actuator_tier(tool) == TIER_READ


@pytest.mark.parametrize("tool", ["create_document", "edit_document", "update_document",
                                  "suggest_document"])
def test_actuator_tier_draft_tools_are_draft(tool):
    assert actuator_tier(tool) == TIER_DRAFT


@pytest.mark.parametrize("tool", ["write_file", "edit_file", "bash", "python", "manage_settings",
                                  # generate_image / edit_image are gated by the base policy
                                  # table, so they are write-gated (not draft) to keep the
                                  # actuator surface a superset of the base gate.
                                  "generate_image", "edit_image"])
def test_actuator_tier_write_tools_are_write_gated(tool):
    assert actuator_tier(tool) == TIER_WRITE


def test_actuator_tier_browser_mcp_is_write_gated():
    assert actuator_tier("browser_click") == TIER_WRITE
    assert actuator_tier("playwright_navigate") == TIER_WRITE


@pytest.mark.parametrize(
    "tool",
    ["send_email", "reply_to_email", "bulk_email",  # people
     "delete_email", "delete_file", "move_file",     # deletion
     "ui_control"],                                   # physical
)
def test_actuator_tier_money_people_deletion_physical_are_hitl_forever(tool):
    assert actuator_tier(tool) == TIER_HITL


# --- method-aware integration calls ----------------------------------------

def test_api_call_read_method_is_read():
    assert actuator_tier("api_call", _api("GET")) == TIER_READ
    assert actuator_tier("app_api", _api("HEAD")) == TIER_READ


def test_api_call_write_method_is_write_gated():
    assert actuator_tier("api_call", _api("POST")) == TIER_WRITE
    assert actuator_tier("api_call", _api("PUT")) == TIER_WRITE


def test_api_call_delete_is_hitl_forever_deletion():
    assert actuator_tier("api_call", _api("DELETE")) == TIER_HITL


def test_api_call_money_target_is_hitl_forever():
    # A write to a financial integration moves money -> never auto-delegated.
    assert actuator_tier("api_call", _api("POST", "/firefly/transactions")) == TIER_HITL
    assert actuator_tier("app_api", _api("POST", "/stripe/charges")) == TIER_HITL


def test_api_call_money_read_is_not_hitl():
    # Reading a balance is fine; only money-moving WRITES are hitl.
    assert actuator_tier("api_call", _api("GET", "/firefly/accounts")) == TIER_READ


# --- fail-closed on unknown / malformed ------------------------------------

@pytest.mark.parametrize("tool", ["totally_unknown_tool", "some_new_actuator", "x"])
def test_actuator_tier_unknown_fails_closed_to_write_gated(tool):
    assert actuator_tier(tool) == TIER_WRITE


def test_actuator_tier_malformed_fails_closed():
    assert actuator_tier(None) == TIER_WRITE
    assert actuator_tier("") == TIER_WRITE
    assert actuator_tier(123) == TIER_WRITE  # type: ignore[arg-type]


def test_api_call_unparseable_content_fails_closed():
    assert actuator_tier("api_call", "not json") == TIER_WRITE
    assert actuator_tier("api_call", None) == TIER_WRITE
    assert actuator_tier("api_call", json.dumps([1, 2])) == TIER_WRITE


# --- requires_approval: read auto-runs, write gates ------------------------

def test_read_auto_runs_even_with_confirm_on(monkeypatch):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: True)
    assert pa.requires_approval("read_file", "x") is False
    assert pa.requires_approval("web_search", "cats") is False
    assert pa.requires_approval("create_document", "draft") is False  # draft too


def test_write_gates_when_confirm_on(monkeypatch):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: True)
    assert pa.requires_approval("write_file", "/tmp/x") is True
    assert pa.requires_approval("bash", "ls") is True
    assert pa.requires_approval("api_call", _api("POST")) is True


def test_write_does_not_gate_when_confirm_off(monkeypatch):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: False)
    assert pa.requires_approval("write_file", "/tmp/x") is False
    assert pa.requires_approval("bash", "ls") is False


# --- requires_approval: unknown defaults gated (fail-closed) ---------------

def test_unknown_defaults_gated_when_confirm_on(monkeypatch):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: True)
    assert pa.requires_approval("totally_unknown_tool", None) is True


def test_unknown_is_mutating_static_failclosed():
    # The fail-closed static path (settings unreadable) must treat unknown and
    # malformed tools as mutating.
    assert pa.is_mutating_tool("totally_unknown_tool") is True
    assert pa.is_mutating_tool(None) is True
    assert pa.is_mutating_tool("bash") is True
    assert pa.is_mutating_tool("web_search") is False  # read is not mutating


# --- hitl-forever gates regardless of settings -----------------------------

@pytest.mark.parametrize(
    "tool,content",
    [("send_email", "..."),            # people
     ("reply_to_email", "..."),        # people
     ("delete_email", "..."),          # deletion
     ("delete_file", "/x"),            # deletion
     ("ui_control", "toggle"),         # physical
     ("api_call", _api("DELETE")),                       # deletion via method
     ("api_call", _api("POST", "/firefly/transactions"))],  # money
)
def test_hitl_forever_gates_even_with_confirm_off(monkeypatch, tool, content):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: False)
    assert pa.requires_approval(tool, content) is True


@pytest.mark.parametrize(
    "tool,content",
    [("send_email", "..."), ("delete_file", "/x"), ("ui_control", "toggle"),
     ("api_call", _api("POST", "/stripe/charges"))],
)
def test_hitl_forever_gates_with_confirm_on(monkeypatch, tool, content):
    monkeypatch.setattr(pa, "confirm_enabled", lambda: True)
    assert pa.requires_approval(tool, content) is True


def test_hitl_forever_is_always_mutating(monkeypatch):
    for tool in ("send_email", "delete_file", "ui_control"):
        assert pa.is_mutating_tool(tool) is True
