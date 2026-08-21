# Model gateway (LiteLLM) — routing and governance

Why odysseus talks to `http://litellm:4000/v1` instead of Ollama on `:11434`,
and which knobs actually bound GPU use.

## The hazard

Ollama sizes its KV cache from the **context window**, not the weights. A caller
that sets `temperature` and `num_predict` but omits `num_ctx` gets the model's
full advertised window, so 17.4GB of weights can load at `size_vram` 53.3GB.
On a 4×3090 host capped at 250W/card that is 1000W — the entire UPS rating.
This happened twice on 2026-08-21 (91%/915W, then 100%/1001W, evicting a
resident 66GB model).

**Model size on disk is not a bound on VRAM.** The gateway pins `num_ctx` per
model, so routing through it bounds VRAM regardless of what the caller asks for.

## Where the endpoint is configured

`OLLAMA_BASE_URL` is injected from Infisical `/odysseus` by `scripts/odys-up.sh`
and therefore **overrides** the default in `docker-compose.yml`. The compose
default is only a backstop for a fresh checkout.

    infisical secrets set OLLAMA_BASE_URL="http://litellm:4000/v1" \
      --projectId=3b559d2b-a3e4-4ed5-bb8f-a0b4b5e00a2c --env=prod \
      --path=/odysseus --domain=https://odin.tailf92846.ts.net

`odys-up.sh` warns at deploy time when this value still points at `:11434`. It
warns rather than overriding: the vault is the source of truth for deployment
config, and a script that quietly overrides it creates drift that is expensive
to debug. Changing it is a deliberate operator action.

Addresses, verified from inside `odysseus-mine-odysseus-1`:

| Address | Result |
| --- | --- |
| `http://litellm:4000/v1` | reachable — **use this** |
| `http://172.18.0.10:4000/v1` | reachable (litellm on `ai_default`) |
| `http://172.18.0.1:4000` | connection refused — port 4000 is never published to the host |

## What `OLLAMA_BASE_URL` actually controls

Less than the name suggests. It feeds exactly two things:

- `src/model_discovery.py` — the host/port scan list for the model picker.
- `app.py` `/api/runtime` — an informational field.

**Chat does not use it.** Inference resolves through the `model_endpoints` table
(`src/endpoint_resolver.py`), whose only enabled row is already
`LiteLLM (traced)` → `http://litellm:4000/v1`, carrying its own key. So the
env var governs discovery, and the database governs inference.

## Gateway credentials

Keys live at Infisical `/homelab/ai`, one per consumer — `ASSISTANT_LITELLM_KEY`
(this app), `OPENWEBUI_LITELLM_KEY`, `LITELLM_AGENTS_KEY`. Per-consumer keys are
what make LiteLLM's per-key model allowlists, rate limits and Langfuse
attribution work; do not collapse them onto one shared key.

`odys-up.sh` fetches **only** this app's key. Do not widen its `run --path` to
`/homelab` or add `--recursive`: that injects `MASTER_KEY`, database passwords
and every service token into the app process, undoing `src/sandbox_env.py`.

Discovery sends the key **only** to the host named by `OLLAMA_BASE_URL` /
`OLLAMA_URL` / `LM_STUDIO_URL` — never to hosts found by the Tailscale/port scan,
which would hand the credential to whatever answers on the LAN.

Note the LiteLLM key file has several secret-shaped fields. The usable
credential is `key` (25 chars, `sk-…`); the 64-hex `token`/`token_id` are its
SHA-256 hash and will 401.

## Two things the environment does NOT bound

Routing through the gateway constrains VRAM per load. It does **not** constrain
*which* model gets loaded.

**1. `ASSISTANT_LITELLM_KEY` is unrestricted** — it lists 17 models including
`qwen3-next:80b`, `gpt-oss:120b` and `llama4:scout`. `LITELLM_AGENTS_KEY` lists
13 and 403s on those three.

**2. Unattended work inherits the last interactive model.** There are 12
`scheduled_tasks` rows (Email AI Auto Reply, Memory Tidy, Calendar Classify,
Skills Audit, …), all with `model = NULL`, so every one resolves its model at
run time.

With `utility_endpoint_id` / `default_endpoint_id` empty, `resolve_endpoint()`
returns `(None, None, None)` for **every** prefix — it needs a non-empty
`{prefix}_endpoint_id` before it will query the endpoint table at all. Callers
then fall through to their own defaults, and
`task_scheduler._resolve_defaults()` takes **the model from the most recent
session** — i.e. whatever a human last chatted with. That is currently
`qwen3-next:80b`, the 66GB model.

Note the `_first_chat_model()` auto-pick (first cached model in gateway order,
also `qwen3-next:80b`) is **not** reachable today for the same reason: nothing
gets as far as the DB query. It arms itself the moment anyone sets a default
endpoint in Settings without also setting a utility model.

### The fix: set the utility pair

`utility_endpoint_id` **and** `utility_model` must both be set. Either alone is
a no-op, verified by simulation against the live resolver:

| Settings | utility | task | research | teacher |
| --- | --- | --- | --- | --- |
| `task_model` only | None | None | None | None |
| `utility_model` only | None | None | None | None |
| **`utility_model` + `utility_endpoint_id`** | `gpt-oss:20b` | `gpt-oss:20b` | `gpt-oss:20b` | `gpt-oss:20b` |

`utility` is the right lever, not `task`: most unattended callers ask for
`utility` directly (`email_pollers`, `builtin_actions`, `context_compactor`,
`note_routes`, `session_routes`, `task_routes`), and every other prefix —
`task`, `research`, `teacher` — falls back to it, because `resolve_endpoint()`
redirects any prefix outside `("utility", "default")` to the utility settings.

Crucially `default` does **not** fall back to utility, so interactive chat keeps
resolving from the session's own model. Bounding unattended work this way costs
no interactive capability, which is why it is preferred over restricting
`ASSISTANT_LITELLM_KEY` or hiding models on the endpoint — both of which would.

Recommended values (`gpt-oss:20b` is single-GPU and already resident at 15.9GB,
so selecting it triggers no cold load):

    utility_endpoint_id = 2ad9dac1b66e4d1699cd325ba20ef484   # LiteLLM (traced)
    utility_model       = gpt-oss:20b

## The credential in the database

`model_endpoints.api_key` holds a gateway key **encrypted in `data/app.db`**,
outside Infisical and outside every environment change above. It is the
credential real chat traffic uses.

Its cached model list contains `qwen3-next:80b`, `gpt-oss:120b` and
`llama4:scout` — the three a restricted key 403s on — so **it is unrestricted**.
It is therefore not `LITELLM_AGENTS_KEY`, and no environment-level change
constrains it.

Rotating or restricting it is a UI/database action (Settings → the
`LiteLLM (traced)` endpoint), not a deploy-time one. Anyone auditing which
models this app can reach must check the endpoint row, not just the environment.

## Embeddings are currently broken (unrelated, pre-existing)

Both lanes fail at startup, so vector RAG, vector memory and the tool index are
degraded:

    src.embeddings   HTTP embedding API unavailable (Request URL is missing an 'http://' or 'https://' protocol.)
    src.embeddings   FastEmbed init failed: Local fastembed is not installed.
    src.rag_vector   VectorRAG init failed: No embedding lanes available

Root cause is not `LLM_HOST` (which resolves to `host.docker.internal`).
`docker-compose.yml` sets `EMBEDDING_URL=""`, and `os.getenv("EMBEDDING_URL",
default)` returns the **empty string** for a set-but-empty variable, so the
built-in default never applies; the FastEmbed fallback then fails because the
package is not in the image. Fixing it needs an embedding model chosen on the
gateway plus `EMBEDDING_API_KEY`, or `fastembed` added to the image.
