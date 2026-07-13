"""Llama-Guard-style taint->sink policy classifier (MR-20, defence-in-depth).

Runs BEHIND the deterministic approval gate (``src/pending_actions`` +
``src/context_taint``), never instead of it. It classifies an action against its
context provenance and escalates the gate's decision along ``allow -> approve ->
block``. By construction it ONLY escalates (final = ``max(base, verdict)``), so a
guard verdict can never downgrade what the gate decided; if the served model is
unavailable the base decision stands (fail-closed to the gate, never fail-open).

Two HARDCODED invariants (no setting/stage/flag bypasses them): HITL-FOREVER
sinks (money, people/messaging/contacts, deletion, physical/home-control) and a
tainted context -> high-blast-radius sink both force human approval. Off-by-
default: the served model is consulted only when configured, else the rule-based
classifier is the floor; ``autonomy_enabled`` defaults DISABLED.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Protocol, Tuple, runtime_checkable


# --- Decision ladder ---------------------------------------------------------

class Decision(str, Enum):
    """Where an action lands. Ordered by severity via ``_RANK``."""

    ALLOW = "allow"      # run freely
    APPROVE = "approve"  # queue for human approval
    BLOCK = "block"      # never run


_RANK = {Decision.ALLOW: 0, Decision.APPROVE: 1, Decision.BLOCK: 2}


def escalate(current: Decision, floor: Decision) -> Decision:
    """Return the MORE severe of two decisions. Never downgrades ``current``."""
    return current if _RANK[current] >= _RANK[floor] else floor


class RiskLevel(str, Enum):
    LOW = "low"
    HIGH = "high"


@dataclass(frozen=True)
class ActionContext:
    """An action plus the provenance needed to classify taint->sink risk."""
    tool_type: Optional[str]
    content: Optional[str] = None
    session_id: Optional[str] = None
    tainted: bool = False
    autonomous: bool = False  # True when self-initiated (no human in the loop)


@dataclass(frozen=True)
class GuardVerdict:
    """A classifier's opinion. ``decision`` is the floor to apply when HIGH."""
    risk: RiskLevel
    decision: Decision = Decision.ALLOW
    category: str = ""
    source: str = "rule"


@dataclass(frozen=True)
class GuardResult:
    decision: Decision
    base: Decision
    reasons: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def escalated(self) -> bool:
        return _RANK[self.decision] > _RANK[self.base]


class GuardUnavailable(Exception):
    """A model-backed guard could not produce a verdict; the orchestrator falls
    back to the deterministic gate (base decision stands) instead of failing open."""


@runtime_checkable
class GuardModel(Protocol):
    """Injectable classifier. Must raise ``GuardUnavailable`` (not return a
    low-risk verdict) when it cannot decide."""
    def classify(self, ctx: ActionContext) -> GuardVerdict: ...


# --- Sink taxonomy (self-contained; no heavy imports) ------------------------

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_METHOD_AWARE_TOOLS = {"api_call", "app_api"}
_BROWSER_PREFIXES = ("browser_", "playwright_")

# HITL-FOREVER categories. Membership here can never be bypassed by any setting.
_MESSAGING_TOOLS = {"send_email", "reply_to_email", "bulk_email", "manage_contact", "send_message", "send_sms"}
_MESSAGING_KEYWORDS = ("message", "contact", "sms", "slack", "telegram", "whatsapp")
_MONEY_KEYWORDS = ("pay", "payment", "transfer", "transaction", "invoice", "billing", "firefly", "checkout", "purchase")
_DELETION_TOOLS = {"delete_file", "move_file"}
_DELETION_KEYWORDS = ("delete", "remove", "destroy", "purge")
_HOME_TOOLS = {"ui_control"}
_HOME_KEYWORDS = ("home_assistant", "hass", "ha_", "light", "lock", "thermostat", "switch", "garage", "door")
_CODE_EXEC_TOOLS = {"bash", "python", "write_file", "edit_file"}  # high-blast, not HITL-forever


def _is_write_api_call(content: Optional[str]) -> bool:
    """api_call/app_api HTTP method inspection; unparseable -> write (fail closed)."""
    if not content:
        return True
    try:
        method = str(json.loads(content).get("method") or "GET").upper()
        return method in _WRITE_METHODS
    except (ValueError, TypeError, AttributeError):
        return True


def _name_has(tool_type: str, keywords: Tuple[str, ...]) -> bool:
    return any(k in tool_type for k in keywords)


def hitl_forever_category(tool_type: Optional[str], content: Optional[str] = None) -> Optional[str]:
    """HITL-FOREVER category (money/people/deletion/home_control), else ``None``.
    These sinks ALWAYS require human approval — no stage/setting/flag can bypass."""
    if not tool_type:
        return None
    name = tool_type.lower()
    body = (content or "").lower()

    if name in _MESSAGING_TOOLS or _name_has(name, _MESSAGING_KEYWORDS):
        return "people"
    if _name_has(name, _MONEY_KEYWORDS) or _name_has(body, _MONEY_KEYWORDS):
        return "money"
    if name in _DELETION_TOOLS or _name_has(name, _DELETION_KEYWORDS):
        return "deletion"
    if name in _METHOD_AWARE_TOOLS:
        try:
            if str(json.loads(content or "{}").get("method") or "").upper() == "DELETE":
                return "deletion"
        except (ValueError, TypeError, AttributeError):
            return "deletion"  # unparseable method -> assume destructive
    if name in _HOME_TOOLS or _name_has(name, _HOME_KEYWORDS):
        return "home_control"
    return None


def is_high_blast_radius(tool_type: Optional[str], content: Optional[str] = None) -> bool:
    """True if the action can cause hard-to-reverse real-world effect: any
    HITL-forever sink, a write API call, a browser action, or code execution."""
    if not tool_type:
        return False
    name = tool_type.lower()
    if hitl_forever_category(name, content):
        return True
    if name in _CODE_EXEC_TOOLS:
        return True
    if name.startswith(_BROWSER_PREFIXES):
        return True
    if name in _METHOD_AWARE_TOOLS:
        return _is_write_api_call(content)
    return False


# --- Classifiers -------------------------------------------------------------

class RuleBasedGuard:
    """Always-available taint->sink classifier: the two hardcoded invariants plus
    an autonomy safety net. No network, so it can never be unavailable."""

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        category = hitl_forever_category(ctx.tool_type, ctx.content)
        if category:
            return GuardVerdict(RiskLevel.HIGH, Decision.APPROVE, category, "rule")
        if ctx.tainted and is_high_blast_radius(ctx.tool_type, ctx.content):
            return GuardVerdict(RiskLevel.HIGH, Decision.APPROVE, "taint->sink", "rule")
        if ctx.autonomous and is_high_blast_radius(ctx.tool_type, ctx.content):
            return GuardVerdict(RiskLevel.HIGH, Decision.APPROVE, "autonomous-high-blast", "rule")
        return GuardVerdict(RiskLevel.LOW, Decision.ALLOW, "", "rule")


_GUARD_PROMPT = (
    "You are a safety classifier guarding an AI assistant that can take "
    "real-world actions. Decide if executing this action in its context is "
    "safe. Answer with 'safe' or 'unsafe' on the first line; if unsafe, add a "
    "short category on the second line.\n\n"
    "Action tool: {tool}\nContext tainted (attacker-controllable): {tainted}\n"
    "Content: {content}\n"
)


class LiteLLMGuard:
    """Model-backed guard (e.g. Llama-Guard served via LiteLLM). ``completion_fn``
    maps a prompt to raw model text — injecting it keeps this class isolated and
    testable. Any model error is surfaced as ``GuardUnavailable`` (not fail-open)."""

    def __init__(self, completion_fn: Callable[[str], str]):
        self._complete = completion_fn

    def classify(self, ctx: ActionContext) -> GuardVerdict:
        prompt = _GUARD_PROMPT.format(
            tool=ctx.tool_type or "",
            tainted=ctx.tainted,
            content=(ctx.content or "")[:2000],
        )
        try:
            raw = self._complete(prompt)
        except Exception as exc:  # network / model failure -> gate applies
            raise GuardUnavailable(str(exc)) from exc
        text = (str(raw) if raw is not None else "").strip().lower()
        if not text:
            raise GuardUnavailable("guard model returned no usable text")
        first = text.splitlines()[0]
        if "unsafe" in first:
            category = text.splitlines()[1].strip() if "\n" in text else "model-unsafe"
            return GuardVerdict(RiskLevel.HIGH, Decision.APPROVE, category, "model")
        return GuardVerdict(RiskLevel.LOW, Decision.ALLOW, "", "model")


# --- Orchestration -----------------------------------------------------------

def guarded_decision(
    ctx: ActionContext,
    base_decision: Decision,
    guard: Optional[GuardModel] = None,
) -> GuardResult:
    """Apply the classifier BEHIND the deterministic gate. Returns ``base_decision``
    escalated (never downgraded) by the hardcoded rule-based invariants and, if
    provided and available, the model guard. An unavailable/erroring model guard
    leaves the base decision intact (fail-closed to the gate)."""
    final = base_decision
    reasons: list[str] = []

    # Hardcoded invariants — always the floor, model or not.
    inv = RuleBasedGuard().classify(ctx)
    if inv.risk is RiskLevel.HIGH:
        final = escalate(final, inv.decision)
        reasons.append(f"invariant:{inv.category}")

    # Optional served model — may escalate further; unavailable -> gate stands.
    if guard is not None:
        try:
            verdict = guard.classify(ctx)
            if verdict.risk is RiskLevel.HIGH:
                final = escalate(final, verdict.decision)
                reasons.append(f"model:{verdict.category}")
        except GuardUnavailable:
            reasons.append("guard-unavailable:deterministic-gate-applies")
        except Exception:  # a buggy guard must never break the caller
            reasons.append("guard-error:deterministic-gate-applies")

    return GuardResult(final, base_decision, tuple(reasons))


# --- Settings-backed wiring (safe/off-by-default) ----------------------------

def _flag(key: str) -> bool:
    try:
        from src.settings import get_setting
        return bool(get_setting(key, False))
    except Exception:
        return False


def autonomy_enabled() -> bool:
    """Global autonomy switch. Defaults DISABLED: nothing self-initiates unless
    the operator explicitly opts in."""
    return _flag("autonomy_enabled")


def guard_classifier_enabled() -> bool:
    """Whether the agent loop consults this classifier. Default OFF so wiring it
    does not change runtime behaviour until an operator turns it on."""
    return _flag("guard_classifier_enabled")


def build_default_guard() -> Optional[GuardModel]:
    """Build the served guard model from ``guard_model`` + ``guard_model_url``
    settings, or ``None`` to use only the rule-based invariants. Never raises —
    a misconfigured model just means the rule-based floor applies."""
    try:
        from src.settings import get_setting
        model = get_setting("guard_model", None)
        url = get_setting("guard_model_url", None)
        if not model or not url:
            return None
        return LiteLLMGuard(_build_completion_fn(str(url), str(model)))
    except Exception:
        return None


def _build_completion_fn(url: str, model: str) -> Callable[[str], str]:
    """Blocking prompt->text call against the guard model; lazy import keeps this
    module free of heavy deps."""

    def _complete(prompt: str) -> str:
        from src.llm_core import llm_call  # lazy: avoids import-time cost
        return llm_call(url, model, [{"role": "user", "content": prompt}])

    return _complete
