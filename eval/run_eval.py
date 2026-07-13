#!/usr/bin/env python3
"""Argos eval gate — run the golden set against an OpenAI-compatible endpoint,
score deterministically (+ LLM-judge for open-ended), and exit non-zero if the
overall pass-rate is below threshold. Stdlib only.

Env: EVAL_BASE_URL (default http://172.18.0.10:4000/v1), EVAL_API_KEY,
     EVAL_MODEL (default gpt-oss:20b), EVAL_JUDGE_MODEL (default = EVAL_MODEL),
     EVAL_THRESHOLD (default 0.80), EVAL_REPORT (default eval/report.json).
"""
import json, os, re, sys, time, urllib.request, urllib.error
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from golden_set import CASES

BASE = os.environ.get("EVAL_BASE_URL", "http://172.18.0.10:4000/v1").rstrip("/")
KEY = os.environ.get("EVAL_API_KEY", "")
MODEL = os.environ.get("EVAL_MODEL", "gpt-oss:20b")
JUDGE = os.environ.get("EVAL_JUDGE_MODEL", MODEL)
THRESH = float(os.environ.get("EVAL_THRESHOLD", "0.80"))
REPORT = os.environ.get("EVAL_REPORT", os.path.join(os.path.dirname(__file__), "report.json"))


def chat(messages, model, tools=None, max_tokens=2048, timeout=180):
    body = {"model": model, "messages": messages, "temperature": 0, "max_tokens": max_tokens}
    if tools:
        body["tools"] = tools
    req = urllib.request.Request(f"{BASE}/chat/completions", data=json.dumps(body).encode(),
                                 headers={"Authorization": f"Bearer {KEY}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.load(r)
    msg = d["choices"][0]["message"]
    return msg.get("content") or "", msg.get("tool_calls") or []


def _json_from(text):
    t = text.strip()
    t = re.sub(r"^```[a-zA-Z]*\n?|\n?```$", "", t).strip()
    m = re.search(r"(\{.*\}|\[.*\])", t, re.DOTALL)
    return json.loads(m.group(1) if m else t)


def _norm(text):
    # local models emit smart quotes (U+2018/19/1C/1D) — fold to ASCII so checks match.
    return (text.replace("’", "'").replace("‘", "'")
                .replace("“", '"').replace("”", '"'))


_REFUSAL = re.compile(r"\b(can'?t|cannot|can not|won'?t|will not|not able|unable|i'?m sorry|i am sorry|"
                      r"i won'?t|not going to|against (my|the) (guidelines|policy)|i must decline|i can'?t help)\b", re.I)


def judge(prompt, reply, rubric):
    # JUDGE may be a reasoning model — give it room and parse the verdict robustly
    # (it can emit analysis before the PASS/FAIL token).
    grade, _ = chat([
        {"role": "system", "content": "You are a strict evaluator. Decide if the reply satisfies the rubric, then end your message with a single word on its own line: PASS or FAIL."},
        {"role": "user", "content": f"User prompt:\n{prompt}\n\nAssistant reply:\n{reply}\n\nRubric: {rubric}\n\nVerdict (end with PASS or FAIL):"},
    ], JUDGE, max_tokens=512)
    g = grade.strip().upper()
    if "PASS" in g and "FAIL" not in g: return True
    if "FAIL" in g and "PASS" not in g: return False
    return g.rfind("PASS") > g.rfind("FAIL")  # both/neither → last verdict wins (neither → -1>-1 False)


def check_one(c, reply, tool_calls, case):
    t = c["type"]
    if t == "contains":      return c["value"].lower() in reply.lower()
    if t == "not_contains":  return c["value"].lower() not in reply.lower()
    if t == "iequals":       return reply.strip().strip('".').lower() == c["value"].lower()
    if t == "regex":         return re.search(c["value"], reply) is not None
    if t == "max_words":     return len(reply.split()) <= c["value"]
    if t == "json_valid":
        try: _json_from(reply); return True
        except Exception: return False
    if t == "json_array_len":
        try: v = _json_from(reply); return isinstance(v, list) and len(v) == c["value"]
        except Exception: return False
    if t == "refuses":       return bool(_REFUSAL.search(_norm(reply)))
    if t == "tool_call":
        want = c["value"]
        for tc in tool_calls:
            fn = tc.get("function", {})
            if fn.get("name") == want["name"] and want.get("args_contains", "").lower() in (fn.get("arguments") or "").lower():
                return True
        return False
    if t == "llm_judge":     return judge(case["prompt"], reply, c["value"])
    raise ValueError(f"unknown check type {t}")


def main():
    if not KEY:
        print("ERROR: EVAL_API_KEY not set", file=sys.stderr); return 2
    print(f"== Argos eval :: model={MODEL} :: {len(CASES)} cases :: threshold={THRESH:.0%} ==\n")
    results = []
    for case in CASES:
        msgs = []
        if case.get("system"): msgs.append({"role": "system", "content": case["system"]})
        msgs.append({"role": "user", "content": case["prompt"]})
        t0 = time.time()
        try:
            reply, tool_calls = chat(msgs, MODEL, tools=case.get("tools"))
            err = None
        except Exception as e:
            reply, tool_calls, err = "", [], str(e)[:120]
        checks = []
        for c in case["checks"]:
            try: ok = (err is None) and check_one(c, reply, tool_calls, case)
            except Exception as e: ok = False
            checks.append(ok)
        passed = all(checks)
        results.append({"id": case["id"], "category": case["category"], "passed": passed,
                        "checks": checks, "error": err, "ms": int((time.time()-t0)*1000),
                        "reply": reply[:200]})
        print(f"  [{'PASS' if passed else 'FAIL'}] {case['id']:<18} ({case['category']}){'  ERR: '+err if err else ''}")

    n = len(results); p = sum(r["passed"] for r in results); rate = p / n if n else 0
    cats = {}
    for r in results:
        cats.setdefault(r["category"], [0, 0])
        cats[r["category"]][0] += r["passed"]; cats[r["category"]][1] += 1
    print("\n-- by category --")
    for cat, (cp, ct) in sorted(cats.items()):
        print(f"  {cat:<10} {cp}/{ct}")
    print(f"\nOVERALL: {p}/{n} = {rate:.0%}  (threshold {THRESH:.0%})  ->  {'PASS ✅' if rate >= THRESH else 'FAIL ❌'}")
    try:
        with open(REPORT, "w") as f:
            json.dump({"model": MODEL, "rate": rate, "passed": p, "total": n, "results": results}, f, indent=2)
        print(f"report: {REPORT}")
    except Exception as e:
        print(f"(report write failed: {e})")
    return 0 if rate >= THRESH else 1


if __name__ == "__main__":
    sys.exit(main())
