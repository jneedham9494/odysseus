# Eval baselines

Reference pass-rates for the openclaw golden set (`eval/golden_set.py`, 21 cases).
Re-run with `bash eval/run.sh` (see `eval/README.md`). Config: `temperature=0`,
`max_tokens=2048`, `EVAL_THRESHOLD=0.80`, LiteLLM router `:4000`.

## Baseline — 2026-06-22 (21 cases)

| model | overall | factual | format | reasoning | concise | tool | safety | helpful |
|---|---|---|---|---|---|---|---|---|
| `gpt-oss:20b` | **21/21 (100%)** | 4/4 | 5/5 | 4/4 | 2/2 | 2/2 | 2/2 | 2/2 |
| `qwen3-coder:30b` | **21/21 (100%)** | 4/4 | 5/5 | 4/4 | 2/2 | 2/2 | 2/2 | 2/2 |
| `qwen3.6:27b` | **21/21 (100%)** | 4/4 | 5/5 | 4/4 | 2/2 | 2/2 | 2/2 | 2/2 |

All three candidate chat models clear the bar. **Promote against these numbers** —
a new model or system-prompt change must hold ≥ its category scores here.

### Gate behaviour proven during baselining
- **Pass path:** 100% → exit 0 → safe to promote.
- **Fail path:** `qwen3.6:27b` at `max_tokens=512` scored 15/21 (71%) → **exit 1**
  (the wrapper propagated the non-zero exit) → gate blocks. Root-caused to the
  token cap starving a *thinking* model of output (empty `content`), not a
  quality regression — fixed by raising the answer budget to 2048. Lesson: when a
  reasoning model regresses on the eval, check `max_tokens` / empty replies before
  concluding it's worse.

### Harness false-negatives caught & fixed at baseline
- **Refusal detection** missed safety refusals because local models write with
  **curly apostrophes** ("I'm sorry, I can't") — now normalised to ASCII before
  matching (`_norm` in `run_eval.py`).
- **LLM-judge** got `max_tokens=8`; reasoning judge models spent it before
  emitting a verdict → empty → false FAIL. Now 512 tokens + robust PASS/FAIL parse.
