# n8n → Assistant Memory Ingest (MR-4)

How the personal-intelligence n8n workflows push records into the assistant's
memory **through the taint-stamped connector write-path** — so automation feeds
cognition without ever bypassing the redaction/taint defenses.

> This is a **wiring note only**. It does NOT modify any live n8n workflow, and
> the interface stays disabled until `INGEST_TOKEN` / `INGEST_OWNER` are set.

## ⚠️ Prerequisite: connector framework (MR-2)

This route depends on the connector framework, which is **NOT yet on
`refactor/base`**:

- `src/connectors/base.py` — `Connector` ABC + `ConnectorRecord`
- `src/connectors/ingest.py` — `ingest_records` (the redaction-enforced write-path)
- `src/context_taint.py` — the `SENSITIVITY_PUBLIC/PERSONAL/SENSITIVE`,
  `TAINT_UNTRUSTED`, `normalize_sensitivity` additions

Until MR-2 is merged, the route mounts and **fully enforces auth (401) and
server-side owner resolution (403)**, but the actual write-path fails closed
with **503** (`connector framework (MR-2) prerequisite not available`). The
framework imports in `routes/connector_routes.py` and `src/connectors/n8n.py`
are guarded so both modules import cleanly on the current base; the guards
become inert no-ops once MR-2 lands and full ingest goes live with no further
code change.

The end-to-end suite (`tests/test_connector_ingest_route.py` on
`feat/n8n-ingest`) requires MR-2 and cannot run on this base. The port ships
`tests/test_connector_ingest_route_base.py`, which covers the security boundary
that runs today (401 / 403 / 422 / 503-fail-closed).

## Endpoint

```
POST https://assistant.tailf92846.ts.net/api/connectors/ingest
Content-Type: application/json
Authorization: Bearer <INGEST_TOKEN>        # or  X-Ingest-Token: <INGEST_TOKEN>
```

The path is auth-exempt at the middleware (an external caller has no session
cookie); the route proves identity with the dedicated `INGEST_TOKEN` itself and
**fails closed** — a missing/wrong token, or no token configured server-side,
returns `401`.

> **app.py wiring (do when enabling):** add `/api/connectors/ingest` to the
> `AUTH_EXEMPT_EXACT` set in `app.py`. The route is mounted via the router
> registry (a `ROUTER_SPECS` entry named `connector_ingest`), but the
> middleware exemption is a separate concern and must be added there when the
> interface is turned on.

### Request body

```json
{
  "workflow": "gmail-triage",
  "records": [
    { "title": "Invoice from Acme", "body": "…", "url": "https://…",
      "published": "2026-07-12T09:00:00Z", "sensitivity": "personal" }
  ]
}
```

- `workflow` — short slug `[a-z0-9][a-z0-9_-]{0,63}`; becomes the provenance tag
  `source_type = connector:n8n:<workflow>`. Invalid slug → `422`.
- `records` — 1..100 records; `body` is required (1..100 000 chars).
- `owner` (batch or per-record) is **advisory** — the server resolves the owner
  from `INGEST_OWNER`. A mismatching claim is rejected with `403`. Per-record
  `source_type`/`owner` are ignored; `ingest_records` stamps the authoritative
  security keys (`taint=untrusted`, `redact=true`, sensitivity, owner).

## Configuration (server-side, Infisical/env)

| Var            | Purpose                                                    |
|----------------|------------------------------------------------------------|
| `INGEST_TOKEN` | Dedicated ingest credential (NOT the loopback token).      |
| `INGEST_OWNER` | Owner silo records land in; must be a known auth user.     |

## Status codes

| Code | Meaning                                                              |
|------|---------------------------------------------------------------------|
| 200  | Ingested (returns `source_type`, `owner`, `seen`, `added`).          |
| 401  | Missing/wrong `INGEST_TOKEN`, or none configured.                   |
| 403  | Body owner disagrees with `INGEST_OWNER`.                           |
| 422  | Invalid batch (caps) or workflow slug.                              |
| 503  | Owner not configured/unknown, RAG down, or MR-2 not yet merged.     |
