"""POST /api/connectors/ingest — auth + owner-resolution tests that hold on
``refactor/base`` WITHOUT the connector framework (MR-2) present.

This is the rebuild/n8n-ingest port. MR-2 (``src/connectors/base.py`` +
``src/connectors/ingest.py`` + the graded-sensitivity constants in
``src/context_taint.py``) is a prerequisite that is NOT on this base, so the
full end-to-end ingest suite (``tests/test_connector_ingest_route.py`` from
feat/n8n-ingest) cannot run here. These tests cover the security boundary that
runs BEFORE the write-path — dedicated-token auth (401) and server-side owner
resolution (403) — which is fully live today, plus the fail-closed 503 the
route returns until MR-2 is merged.

Fully offline: no ChromaDB / numpy / embedding. When the framework is absent
the route never reaches the write-path.
"""
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from routes.connector_routes import _CONNECTOR_FRAMEWORK, setup_connector_routes


class _FakeAuth:
    is_configured = True

    def __init__(self, users):
        self.users = users


def _client(monkeypatch, *, token="tok-secret", owner="jack", auth=None) -> TestClient:
    if token is not None:
        monkeypatch.setenv("INGEST_TOKEN", token)
    else:
        monkeypatch.delenv("INGEST_TOKEN", raising=False)
    if owner is not None:
        monkeypatch.setenv("INGEST_OWNER", owner)
    else:
        monkeypatch.delenv("INGEST_OWNER", raising=False)
    app = FastAPI()
    app.include_router(setup_connector_routes())
    app.state.auth_manager = auth  # None → skip known-user check
    return TestClient(app)


def _auth(token="tok-secret"):
    return {"Authorization": f"Bearer {token}"}


def _batch(**over):
    body = {"workflow": "gmail-triage", "records": [{"body": "hello world"}]}
    body.update(over)
    return body


# --- auth (401): runs before any framework dependency ---------------------

def test_unauthenticated_request_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch())
    assert r.status_code == 401


def test_wrong_token_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth("nope"))
    assert r.status_code == 401


def test_no_token_configured_fails_closed(monkeypatch):
    client = _client(monkeypatch, token=None)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth("anything"))
    assert r.status_code == 401


# --- owner resolution (403 / 503): runs before the write-path -------------

def test_caller_cannot_write_to_another_owner(monkeypatch):
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(owner="attacker"),
                    headers=_auth())
    assert r.status_code == 403


def test_matching_owner_claim_passes_owner_check(monkeypatch):
    # A matching owner claim must NOT be rejected at the owner gate. Without the
    # framework the route then fails closed at 503; with it, it would ingest.
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(owner="JACK"),
                    headers=_auth())
    assert r.status_code != 403
    assert r.status_code == (503 if not _CONNECTOR_FRAMEWORK else 200)


def test_no_owner_configured_fails_closed(monkeypatch):
    client = _client(monkeypatch, owner=None)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503


def test_owner_must_be_known_user_when_auth_configured(monkeypatch):
    auth = _FakeAuth(users={"jack": {}})
    client = _client(monkeypatch, owner="ghost", auth=auth)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503  # configured owner is not a real silo


# --- batch / slug validation (422): runs before the write-path ------------

def test_oversized_batch_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    records = [{"body": f"item {i}"} for i in range(101)]  # cap is 100
    r = client.post("/api/connectors/ingest", json=_batch(records=records),
                    headers=_auth())
    assert r.status_code == 422


def test_empty_batch_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch(records=[]),
                    headers=_auth())
    assert r.status_code == 422


def test_invalid_workflow_slug_is_rejected(monkeypatch):
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest",
                    json=_batch(workflow="bad slug!!"), headers=_auth())
    assert r.status_code == 422


# --- stub behaviour on this base (503 until MR-2 merges) ------------------

@pytest.mark.skipif(_CONNECTOR_FRAMEWORK,
                    reason="connector framework present → route reaches write-path")
def test_write_path_fails_closed_without_framework(monkeypatch):
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503


# --- registry wiring ------------------------------------------------------

def test_connector_ingest_registered_in_router_specs():
    from routes.registry import ROUTER_SPECS

    assert any(spec.name == "connector_ingest" for spec in ROUTER_SPECS)


def test_sanitize_workflow_is_framework_free():
    from src.connectors.n8n import sanitize_workflow

    assert sanitize_workflow(None) == "default"
    assert sanitize_workflow("Gmail-Triage") == "gmail-triage"
    assert sanitize_workflow("bad slug!!") is None
