# Agent Security Posture (openclaw fork)

Foundation-phase hardening (W2): make prompt-injection and rogue/buggy agent
behaviour structurally unable to leak secrets or take unapproved real-world
actions. Threat model is a single-user, Tailscale-only box — the dominant risks
are (1) the agent mutating something it shouldn't, (2) indirect prompt-injection
via fetched web/email content driving exfiltration, not external intruders.

## Defenses in place

| Layer | What | Where |
|---|---|---|
| **No secrets to agent code** | bash/python/bg-jobs get a secret-free env built from an allowlist, never `os.environ`. `env` in agent code reveals 0 of the app's API keys. | `src/sandbox_env.py`; wired in `tool_execution._direct_fallback`, `bg_jobs` |
| **RAG redaction** | Secrets + hard IDs (API keys, JWTs, PEM keys, Luhn cards, IBAN, SSN) are masked before embedding/storing. Can't leak via RAG what was never indexed. Opt out per-doc with `{"redact": False}`. | `src/rag_redaction.py`; wired in `rag_vector.add_document(_batch)` |
| **Fail-closed approval** | If the approval policy can't be evaluated, mutating tools are gated (not run) unless confirm is clearly off. | `agent_loop._needs_approval`, `pending_actions.is_mutating_tool` |
| **Tier-split (EchoLeak defense)** | Once a session ingests untrusted web/browser content it is *tainted*; later credentialed actions (send/reply/bulk_email, write api_call/app_api, browser_*) are forced through approval even if auto-confirm is off. | `src/context_taint.py`; gate in `agent_loop` |
| **Least privilege** | App env holds only its own service API keys — NO restic/LUKS/Infisical-admin/Tailscale/B2 crown-jewels; no sensitive host mounts; `.ssh` empty. | verified 2026-06-22 |
| **Approval queue** | Mutating/real-world tools stash for one-tap human approval (method-aware for api_call). Email has its own `agent_email_confirm` (default on). | `src/pending_actions.py`, `routes/pending_routes.py` |

## Known residual risk / deliberate follow-up

**Egress isolation for code-exec is NOT yet enforced.** bash/python run inside
the app container (as root, on a network with internet). Env secrets are stripped
and credentialed *actions* are taint-gated, but agent code could still read
non-secret in-container data and POST it out, or a tainted session could
`web_fetch` an attacker URL (reads aren't gated, to keep multi-page research
usable).

Proper fix = run code-exec in a **separate sandbox container** on an internal
(`internal: true`) network with an egress allowlist proxy, non-root, read-only
rootfs, no secret mounts. In-container `unshare --net` is not viable here (needs
CAP_SYS_ADMIN, which the app container doesn't and shouldn't have). Tracked as a
future hardening; the env-strip + tier-split cover the highest-value vectors in
the meantime.
