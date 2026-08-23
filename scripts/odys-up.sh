#!/bin/bash
# Deploy the odysseus-mine assistant with secrets from Infisical (/odysseus path).
set -uo pipefail
INF="$HOME/.local/bin/infisical"; DOMAIN="https://odin.tailf92846.ts.net"; PID=3b559d2b-a3e4-4ed5-bb8f-a0b4b5e00a2c
. "$HOME/.config/infisical/odin-host.env"
export INFISICAL_TOKEN="$("$INF" login --method=universal-auth --client-id="$INFISICAL_CLIENT_ID" --client-secret="$INFISICAL_CLIENT_SECRET" --domain="$DOMAIN" --plain)"
cd /mnt/fast/home/Projects/apps/odysseus-mine

# LiteLLM gateway key for model discovery. It lives at /homelab/ai alongside the
# other per-consumer gateway keys (OPENWEBUI_LITELLM_KEY, LITELLM_AGENTS_KEY),
# not under /odysseus, so fetch exactly this one secret. Do NOT widen the
# `run --path` below to /homelab or add --recursive: that would inject every
# homelab credential (MASTER_KEY, DB passwords, tokens) into the app process and
# undo the secret-free subprocess work in src/sandbox_env.py.
LITELLM_API_KEY="$("$INF" secrets get ASSISTANT_LITELLM_KEY --projectId="$PID" \
  --env=prod --path=/homelab/ai --domain="$DOMAIN" --plain 2>/dev/null)"
export LITELLM_API_KEY
if [ -z "$LITELLM_API_KEY" ]; then
  echo "odys-up: WARNING - ASSISTANT_LITELLM_KEY not found at /homelab/ai." >&2
  echo "odys-up:   Model discovery will get 401 from the gateway and list no models." >&2
  echo "odys-up:   Chat itself is unaffected (the 'LiteLLM (traced)' endpoint" >&2
  echo "odys-up:   carries its own key in the app DB). Continuing." >&2
fi

# Preflight: OLLAMA_BASE_URL is injected from the vault below and therefore WINS
# over the default in docker-compose.yml. Warn (don't override) when it still
# points at raw Ollama, so a stale vault value can't silently bypass the gateway.
# We warn rather than export our own: the vault is the source of truth for
# deployment config, and a script that quietly overrides it produces exactly the
# drift that makes these bugs expensive to find.
_endpoint="$("$INF" secrets get OLLAMA_BASE_URL --projectId="$PID" \
  --env=prod --path=/odysseus --domain="$DOMAIN" --plain 2>/dev/null)"
case "$_endpoint" in
  *:11434*)
    echo "odys-up: WARNING - OLLAMA_BASE_URL at Infisical /odysseus is '$_endpoint'," >&2
    echo "odys-up:   which bypasses the LiteLLM gateway and its per-model num_ctx cap." >&2
    echo "odys-up:   An unbounded cold load can size its KV cache to the model's full" >&2
    echo "odys-up:   context window and claim every GPU on the host. To fix:" >&2
    echo "odys-up:     infisical secrets set OLLAMA_BASE_URL=\"http://litellm:4000/v1\" \\" >&2
    echo "odys-up:       --projectId=$PID --env=prod --path=/odysseus --domain=$DOMAIN" >&2
    echo "odys-up:   Continuing with the vault value." >&2
    ;;
esac
unset _endpoint

# Stamp the build with the commit it came from so the deployed artefact can be
# compared against the repo instead of assumed to match it. Falls back to
# "unknown" outside a checkout rather than failing: a missing stamp should make
# the deploy check say "cannot prove", not block a deploy that is otherwise fine.
GIT_COMMIT="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
export GIT_COMMIT

exec "$INF" run --projectId="$PID" --env=prod --path=/odysseus --domain="$DOMAIN" -- docker compose "$@"
