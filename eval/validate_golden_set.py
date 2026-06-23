#!/usr/bin/env python3
"""Network-free structural check for the eval golden set — runs in GitHub CI
(which can't reach the tailnet-only models, so it can't run the real eval).
Catches a broken golden set / unknown check type before it reaches the gate.
Exits non-zero on any structural problem.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from golden_set import CASES

# Keep in sync with check_one() in run_eval.py.
KNOWN_CHECKS = {"contains", "not_contains", "iequals", "regex", "max_words",
                "json_valid", "json_array_len", "tool_call", "refuses", "llm_judge"}
VALUE_REQUIRED = KNOWN_CHECKS - {"json_valid", "refuses"}

errs = []
seen = set()
for i, c in enumerate(CASES):
    where = f"case[{i}] id={c.get('id', '?')}"
    for field in ("id", "category", "prompt", "checks"):
        if not c.get(field):
            errs.append(f"{where}: missing/empty '{field}'")
    cid = c.get("id")
    if cid in seen:
        errs.append(f"{where}: duplicate id")
    seen.add(cid)
    for chk in c.get("checks", []):
        t = chk.get("type")
        if t not in KNOWN_CHECKS:
            errs.append(f"{where}: unknown check type {t!r}")
        if t in VALUE_REQUIRED and "value" not in chk:
            errs.append(f"{where}: check {t!r} requires a 'value'")
        if t == "tool_call":
            if not c.get("tools"):
                errs.append(f"{where}: tool_call check but no 'tools' provided")
            if not isinstance(chk.get("value"), dict) or "name" not in chk.get("value", {}):
                errs.append(f"{where}: tool_call value needs a 'name'")

if errs:
    print(f"GOLDEN SET INVALID ({len(errs)} problem(s)):")
    for e in errs:
        print("  -", e)
    sys.exit(1)
print(f"golden set OK: {len(CASES)} cases, {sum(len(c['checks']) for c in CASES)} checks, "
      f"categories={sorted({c['category'] for c in CASES})}")
