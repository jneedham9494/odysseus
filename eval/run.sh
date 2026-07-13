#!/bin/bash
# Argos eval gate — run the golden set through the assistant's own LiteLLM
# (traced) endpoint and exit non-zero if pass-rate < EVAL_THRESHOLD.
#
# The endpoint's base_url + api_key are resolved from the running container's
# ModelEndpoint DB record (the SAME endpoint the assistant uses), so the eval
# needs no separate secret: the key never leaves the container, and there is no
# Infisical dependency to drift. Runs ON ODIN (tailnet-only models + the LiteLLM
# router are unreachable from GitHub runners); LiteLLM adds Langfuse traces.
#
#   bash eval/run.sh                                  # LiteLLM (traced), gpt-oss:20b
#   EVAL_MODEL=qwen3-coder:30b bash eval/run.sh
#   EVAL_ENDPOINT="Ollama" bash eval/run.sh           # score via a different named endpoint
#   EVAL_CONTAINER=some-other-container bash eval/run.sh
set -uo pipefail

CONTAINER="${EVAL_CONTAINER:-odysseus-mine-odysseus-1}"

exec docker exec \
  -e EVAL_MODEL="${EVAL_MODEL:-gpt-oss:20b}" \
  -e EVAL_THRESHOLD="${EVAL_THRESHOLD:-0.80}" \
  -e EVAL_JUDGE_MODEL="${EVAL_JUDGE_MODEL:-}" \
  -e EVAL_ENDPOINT="${EVAL_ENDPOINT:-LiteLLM (traced)}" \
  "$CONTAINER" python -c '
import os
from core.database import SessionLocal, ModelEndpoint

name = os.environ["EVAL_ENDPOINT"]
db = SessionLocal()
ep = db.query(ModelEndpoint).filter(ModelEndpoint.name == name).first()
if ep is None:
    raise SystemExit(f"eval: ModelEndpoint {name!r} not found in the app DB")
os.environ["EVAL_BASE_URL"] = ep.base_url
os.environ["EVAL_API_KEY"] = ep.api_key or ""
if not os.environ.get("EVAL_JUDGE_MODEL"):
    os.environ.pop("EVAL_JUDGE_MODEL", None)  # run_eval defaults judge = model

import runpy
runpy.run_path("/app/eval/run_eval.py", run_name="__main__")
'
