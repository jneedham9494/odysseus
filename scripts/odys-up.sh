#!/bin/bash
# Deploy the odysseus-mine assistant with secrets from Infisical (/odysseus path).
set -uo pipefail
INF="$HOME/.local/bin/infisical"; DOMAIN="https://odin.tailf92846.ts.net"; PID=3b559d2b-a3e4-4ed5-bb8f-a0b4b5e00a2c
. "$HOME/.config/infisical/odin-host.env"
export INFISICAL_TOKEN="$("$INF" login --method=universal-auth --client-id="$INFISICAL_CLIENT_ID" --client-secret="$INFISICAL_CLIENT_SECRET" --domain="$DOMAIN" --plain)"
cd /mnt/fast/home/Projects/apps/odysseus-mine
exec "$INF" run --projectId="$PID" --env=prod --path=/odysseus --domain="$DOMAIN" -- docker compose "$@"
