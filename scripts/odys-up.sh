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

exec "$INF" run --projectId="$PID" --env=prod --path=/odysseus --domain="$DOMAIN" -- docker compose "$@"
