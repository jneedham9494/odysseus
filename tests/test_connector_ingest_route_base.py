"""POST /api/connectors/ingest — the route's security boundary and its handoff
to the shared write-path.

The boundary that runs BEFORE anything is written: dedicated-token auth (401),
server-side owner resolution (403/503) and batch/slug validation (422). Past
that gate the route hands the batch to
:func:`src.connectors.ingest.ingest_records`, which is stubbed here so the
handoff can be asserted directly — that the batch is passed under the
SERVER-resolved owner, and that a refused request never reaches it at all.

Fully offline: no ChromaDB / numpy / embedding. The write-path is replaced by
:class:`_RecordedIngest`, so nothing here depends on a reachable vector store.
``tests/test_connector_ingest.py`` covers what ``ingest_records`` itself does
with the records once it has them.

HISTORY: this file was ported onto ``refactor/base`` when the connector
framework (MR-2) was still a pending prerequisite, and it asserted the
fail-closed 503 the route returned until then. MR-2 has since landed, so the
write-path is reached; the guard that returns 503 without the framework is
still pinned below, by patching the flag rather than by depending on which
branch the tests happen to run on.
"""
from fastapi import FastAPI
from fastapi.testclient import TestClient

import routes.connector_routes as connector_routes
from routes.connector_routes import setup_connector_routes
from src.connectors.base import IngestResult


class _FakeAuth:
    is_configured = True

    def __init__(self, users):
        self.users = users


class _RecordedIngest:
    """Stand-in for the shared write-path: records the call, returns a canned
    result. Lets the route be tested without a vector store behind it."""

    def __init__(self, result: IngestResult):
        self.result = result
        self.calls: list[tuple[object, str, list]] = []

    def __call__(self, connector, owner, records) -> IngestResult:
        self.calls.append((connector, owner, list(records)))
        return self.result

    @property
    def owners(self) -> list[str]:
        return [owner for _, owner, _ in self.calls]


def _stub_write_path(monkeypatch, *, success=True, message="", seen=1, added=1):
    stub = _RecordedIngest(
        IngestResult(success=success, message=message, seen=seen, added=added)
    )
    monkeypatch.setattr(connector_routes, "ingest_records", stub)
    return stub


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
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch())
    assert r.status_code == 401
    assert not stub.calls


def test_wrong_token_is_rejected(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth("nope"))
    assert r.status_code == 401
    assert not stub.calls


def test_no_token_configured_fails_closed(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch, token=None)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth("anything"))
    assert r.status_code == 401
    assert not stub.calls


# --- owner resolution (403 / 503): runs before the write-path -------------

def test_caller_cannot_write_to_another_owner(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(owner="attacker"),
                    headers=_auth())
    assert r.status_code == 403
    assert not stub.calls


def test_matching_owner_claim_reaches_write_path_as_server_owner(monkeypatch):
    # A matching owner claim must NOT be rejected at the owner gate — and what
    # reaches the write-path is the SERVER-side owner, not the caller's casing.
    stub = _stub_write_path(monkeypatch, seen=1, added=1)
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(owner="JACK"),
                    headers=_auth())
    assert r.status_code == 200
    assert stub.owners == ["jack"]
    assert r.json() == {
        "ok": True,
        "source_type": "connector:n8n:gmail-triage",
        "owner": "jack",
        "seen": 1,
        "added": 1,
    }


def test_no_owner_configured_fails_closed(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch, owner=None)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503
    assert not stub.calls  # 503 from the owner gate, not from a down write-path


def test_owner_must_be_known_user_when_auth_configured(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    auth = _FakeAuth(users={"jack": {}})
    client = _client(monkeypatch, owner="ghost", auth=auth)
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503  # configured owner is not a real silo
    assert not stub.calls


# --- batch / slug validation (422): runs before the write-path ------------

def test_oversized_batch_is_rejected(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch)
    records = [{"body": f"item {i}"} for i in range(101)]  # cap is 100
    r = client.post("/api/connectors/ingest", json=_batch(records=records),
                    headers=_auth())
    assert r.status_code == 422
    assert not stub.calls


def test_empty_batch_is_rejected(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest", json=_batch(records=[]),
                    headers=_auth())
    assert r.status_code == 422
    assert not stub.calls


def test_invalid_workflow_slug_is_rejected(monkeypatch):
    stub = _stub_write_path(monkeypatch)
    client = _client(monkeypatch)
    r = client.post("/api/connectors/ingest",
                    json=_batch(workflow="bad slug!!"), headers=_auth())
    assert r.status_code == 422
    assert not stub.calls


# --- write-path outcomes --------------------------------------------------

def test_failed_write_is_reported_as_503_not_partial_success(monkeypatch):
    # RAG down / owner missing → the route surfaces a service error so n8n
    # retries, rather than reporting a write that did not happen.
    stub = _stub_write_path(monkeypatch, success=False,
                            message="rag unavailable", seen=1, added=0)
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503
    # The owner gate and the framework guard both 503 too, so pin that this
    # one came from the write-path having actually run and reported failure.
    assert stub.owners == ["jack"]


def test_write_path_fails_closed_without_framework(monkeypatch):
    # The guarded import in the route is the last line of defence if the
    # connector framework ever goes missing: no framework, no write. Patched
    # rather than inferred, so this holds wherever the suite runs.
    stub = _stub_write_path(monkeypatch)
    monkeypatch.setattr(connector_routes, "_CONNECTOR_FRAMEWORK", False)
    client = _client(monkeypatch, owner="jack")
    r = client.post("/api/connectors/ingest", json=_batch(), headers=_auth())
    assert r.status_code == 503
    assert not stub.calls


# --- registry wiring ------------------------------------------------------

def test_connector_ingest_registered_in_router_specs():
    from routes.registry import ROUTER_SPECS

    assert any(spec.name == "connector_ingest" for spec in ROUTER_SPECS)


def test_sanitize_workflow_is_framework_free():
    from src.connectors.n8n import sanitize_workflow

    assert sanitize_workflow(None) == "default"
    assert sanitize_workflow("Gmail-Triage") == "gmail-triage"
    assert sanitize_workflow("bad slug!!") is None
