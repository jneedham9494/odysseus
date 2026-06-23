# openclaw eval gate

A small, dependency-free golden-set eval that answers one question before you
promote a **model or system-prompt change**: *did it get worse?*

It runs ~20 task-representative prompts through the LiteLLM router (the same
endpoint the assistant uses), scores each with deterministic checks (+ an
LLM-judge for open-ended ones), and **exits non-zero if the pass-rate drops
below threshold**. That non-zero exit is the gate.

## Why it lives here and runs on odin (not GitHub CI)

The models are served by host Ollama behind LiteLLM on the **tailnet only** —
GitHub-hosted runners cannot reach them. So this is a **local pre-promotion
gate** run on odin, not a cloud CI job. (A self-hosted runner joined to the
tailnet could automate it later — see *Automating* below.) It's stdlib-only
Python (the host has no node, so promptfoo/DeepEval were out) — nothing to
`pip install`, nothing to `npm install`.

## Run it

```bash
# on odin, from the repo root — pulls ASSISTANT_LITELLM_KEY from Infisical:
bash eval/run.sh                              # default model gpt-oss:20b
EVAL_MODEL=qwen3-coder:30b bash eval/run.sh   # eval a different model
EVAL_MODEL=qwen3.6:27b     bash eval/run.sh
```

`run.sh` logs into Infisical with the `odin-host` machine identity, injects the
assistant's `ASSISTANT_LITELLM_KEY`, and runs `run_eval.py`. No `.env`, no
pasted keys.

## The gate workflow

1. **Baseline** the current model: `bash eval/run.sh`; the printed pass-rate +
   `eval/report.json` are your reference (also recorded in `BASELINE.md`).
2. **Before promoting** a new model or editing the system prompt, run the eval
   against the candidate. If the rate **drops below the baseline / threshold**,
   the run exits non-zero — don't promote.
3. Investigate the FAILing case ids in the output / `report.json`, fix or accept,
   re-run.

## Knobs (env vars)

| var | default | meaning |
|---|---|---|
| `EVAL_MODEL` | `gpt-oss:20b` | model under test (any LiteLLM model name) |
| `EVAL_JUDGE_MODEL` | = `EVAL_MODEL` | model that grades `llm_judge` cases |
| `EVAL_THRESHOLD` | `0.80` | min overall pass-rate to exit 0 |
| `EVAL_BASE_URL` | `http://172.18.0.10:4000/v1` | LiteLLM OpenAI-compatible base (use `http://litellm:4000/v1` from inside a container on `ai_default`) |
| `EVAL_API_KEY` | — | set by `run.sh` from Infisical; overrideable |
| `EVAL_REPORT` | `eval/report.json` | machine-readable results |

## The golden set (`golden_set.py`)

~20 cases across **factual, format/instruction-following, reasoning,
conciseness, tool-calling, safety/refusal, helpfulness**. Each case has
`checks` — assertions of type `contains`, `iequals`, `regex`, `max_words`,
`json_valid`, `json_array_len`, `tool_call`, `refuses`, or `llm_judge`. Add a
case = append a dict. **This file is the contract** — grow it as the assistant
takes on new task types.

## Automating later

To make this a true blocking CI step, register a **self-hosted GitHub runner on
the tailnet** and add a job that runs `bash eval/run.sh` on model/prompt-change
PRs. Until then it's a manual pre-promotion gate (documented in
`docs/AGENT_SECURITY.md` / the foundation plan, W3.2).
