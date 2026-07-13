#!/bin/bash
# Argos eval gate — pull the assistant's LiteLLM key from Infisical and run the
# golden set against the LiteLLM router. Runs ON ODIN (tailnet-only models are
# unreachable from GitHub runners). Exits non-zero if pass-rate < EVAL_THRESHOLD.
#
#   bash eval/run.sh                       # default model (gpt-oss:20b)
#   EVAL_MODEL=qwen3-coder:30b bash eval/run.sh
#   EVAL_BASE_URL=http://litellm:4000/v1 bash eval/run.sh   # from inside a container
set -uo pipefail
INF="$HOME/.local/bin/infisical"; DOMAIN="https://odin.tailf92846.ts.net"; PID=3b559d2b-a3e4-4ed5-bb8f-a0b4b5e00a2c
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HOME/.config/infisical/odin-host.env"
export INFISICAL_TOKEN="$("$INF" login --method=universal-auth --client-id="$INFISICAL_CLIENT_ID" --client-secret="$INFISICAL_CLIENT_SECRET" --domain="$DOMAIN" --plain)"
# ASSISTANT_LITELLM_KEY (the assistant's own LiteLLM virtual key) lives in the
# Infisical ROOT path (core secrets), not /odysseus, and becomes EVAL_API_KEY.
exec "$INF" run --projectId="$PID" --env=prod --domain="$DOMAIN" -- \
  bash -c 'EVAL_API_KEY="${EVAL_API_KEY:-$ASSISTANT_LITELLM_KEY}" python3 "'"$DIR"'/run_eval.py"'
