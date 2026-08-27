# odysseus-mine — CLAUDE.md

> **Jack's private fork of Odysseus** = **"Argos"**, the personal AI assistant (named for
> Odysseus's faithful hound). NOTE: modeled on — but NOT using — the OpenClaw product. The
> `README.md` here is upstream Odysseus's — *this* file is the fork's reality. For the broader
> odin/homelab context, read **`/mnt/fast/home/Projects/homelab/CLAUDE.md`** first.

## What it is
A fork of **Odysseus** (FastAPI / Python) — a self-hosted agentic assistant (chat, agents,
RAG, tools, voice, approval queue). Live on **odin** at `assistant.tailf92846.ts.net`
(binds `100.112.242.31:7001`). Work on the **`dev`** branch. Admin login **`jack`** —
password in Infisical `/odysseus → ODYSSEUS_ADMIN_PASSWORD` (don't print it).

## Deploy / dev loop (important)
- Compose project `odysseus-mine`; container `odysseus-mine-odysseus-1`; app on port 7000
  (published `100.112.242.31:7001`). Dual-homed on the `homelab` + `ai_default` networks.
- **Baked image** (`build: .`): `src/` is **NOT bind-mounted** → **code changes require a
  rebuild**: `docker compose build odysseus && … up -d`. `tests/` and `eval/` aren't baked →
  run via a repo-mount (`docker run --rm -v $PWD:/work -w /work --entrypoint python … -m pytest`).
- **Deploy:** `bash scripts/odys-up.sh up -d` (injects Infisical `--path=/odysseus`).
- **Models:** everything goes through the **LiteLLM gateway** (`http://litellm:4000/v1`),
  never raw Ollama on `:11434`. The gateway pins `num_ctx` per model; without that bound a
  17GB model loaded into 53GB of VRAM and drove the UPS to 915W then 1001W on 2026-08-21
  (per `docs/MODEL_GATEWAY.md`, which records both). Two mechanisms, and confusing them is
  the trap:
  - **Chat resolves through the `model_endpoints` table** (`src/endpoint_resolver.py`), whose
    only enabled row is **"LiteLLM (traced)"** → `http://litellm:4000/v1`. *This* is the
    inference path, and the tracing is a side effect of it rather than its purpose.
  - `OLLAMA_BASE_URL` governs **model discovery only** (`src/model_discovery.py`) plus an
    informational `/api/runtime` field — it does not route chat. The deployed value comes from
    Infisical `/odysseus` and **overrides** the compose default, so `docker-compose.yml` is a
    backstop for a fresh checkout rather than a statement of what is running.
    `scripts/odys-up.sh` warns at deploy time if the vault value still points at `:11434`.
  Picking a `qwen3-agent` model routes through the toggle-able vLLM (see homelab CLAUDE.md).
  **Read [`docs/MODEL_GATEWAY.md`](docs/MODEL_GATEWAY.md) before changing any of this** — the
  addresses are recorded there with what each one actually did when tried from inside the
  container.

## What's hardened (foundation W2/W3 — don't regress)
- `src/sandbox_env.py` — bash/python tools get a **secret-free** subprocess env (was leaking all 9 app secrets via `os.environ`).
- `src/context_taint.py` — **tier-split**: once a session ingests untrusted web/email content, credentialed mutators are forced through approval (EchoLeak defense), fail-closed.
- `src/rag_redaction.py` — masks secrets/PII (API keys, JWT, PEM, cards, IBAN, SSN) **before embedding**.
- Approval queue `src/pending_actions.py` + `routes/pending_routes.py` — mutating tools held for one-tap ntfy approve; `_needs_approval` **fails closed**. `send_email` self-gates via `agent_email_confirm`.
- `docs/AGENT_SECURITY.md` documents the posture (incl. the deferred egress-sandbox follow-up).

## Eval gate (`eval/`) — run before promoting a model/prompt
`bash eval/run.sh` (on odin) — a **stdlib-only** golden set (~21 cases) scored against LiteLLM;
exits non-zero below threshold (the gate). Runs **on odin** (tailnet-only models unreachable
from GitHub CI). CI has a network-free structural validator (`eval/validate_golden_set.py`).
Baselines in `eval/BASELINE.md`. **Run it after any model or system-prompt change.**

## Integrations (live, via `POST /api/auth/integrations`)
Miniflux · Home Assistant · AdGuard · Firefly III · **ntopng** — plus a Playwright browser MCP
and an HA→assistant event webhook. RAG indexes Obsidian/Paperless/Memos into ChromaDB.

## Conventions
- Work on **`dev`**. Don't commit secrets. User defaults to **commit-now/push-later**.
  Pushing changes to `.github/workflows/` over **HTTPS fails** (OAuth lacks `workflow` scope) —
  push that commit via the **SSH** remote (`git@github.com:jneedham9494/odysseus.git`).
- A few source files were once root-owned (blocked scp) — `sudo chown odinadmin` if needed.
- **Theme system:** custom themes persist per-user in `data/user_prefs.json` under
  `_users.<user>.custom-themes` (5 base colours `bg/fg/panel/border/red`; the app *derives*
  syntax/accent colours). `static/` is baked. A "Kanagawa Wave" theme is installed for `jack`.
