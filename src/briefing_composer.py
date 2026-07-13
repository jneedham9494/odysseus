"""Daily-briefing composer.

Gathers the three context lanes a morning briefing cares about — calendar
events, RSS/feed items, and open tasks/reminders — and renders them into a
single, *bounded*, *item-covering* briefing string.

Two guarantees the renderer makes (and the tests pin):

* **Bounded** — the output never exceeds ``max_total_chars``. Long inputs are
  truncated deterministically rather than dumping unbounded data into a prompt
  or a push notification.
* **Item-covering** — every section header carries the *total* count of items
  in that lane, so even when the body is capped at ``max_items_per_section``
  the reader still sees how many items exist (shown items + a trailing
  ``…and N more`` line). No item silently disappears from the tally.

The composed string is used two ways:

1. As a deterministic draft injected into the daily-briefing scheduled task's
   agent prompt (see ``src/task_scheduler.py``), which the agent then enriches
   (live feeds via Miniflux), delivers (ntfy + session), and mines for durable
   facts (``manage_memory`` → fires ``memory_added``).
2. Directly as a fallback briefing when no model is available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

# Importance ranking used to order calendar events (highest first) and to
# pick the leading glyph. Mirrors CalendarEvent.importance values.
_IMPORTANCE_RANK: dict[str, int] = {"critical": 3, "high": 2, "normal": 1, "low": 0}
_IMPORTANCE_GLYPH: dict[str, str] = {"critical": "[!!] ", "high": "[!] ", "normal": "", "low": " · "}

# Task priority ranking (highest first).
_PRIORITY_RANK: dict[str, int] = {"high": 2, "normal": 1, "low": 0}


@dataclass(frozen=True)
class CalendarItem:
    """One upcoming calendar event."""
    title: str
    when: str                       # human-readable time, e.g. "09:30"
    importance: str = "normal"      # low | normal | high | critical
    location: str | None = None
    kind: str | None = None         # work | personal | health | travel | ...


@dataclass(frozen=True)
class FeedItem:
    """One unread RSS / news item."""
    title: str
    source: str
    url: str | None = None


@dataclass(frozen=True)
class TaskItem:
    """One open task / reminder."""
    title: str
    due: str | None = None
    priority: str = "normal"        # low | normal | high


@dataclass
class BriefingContext:
    """Everything a single day's briefing is rendered from."""
    date_label: str
    calendar: list[CalendarItem] = field(default_factory=list)
    feeds: list[FeedItem] = field(default_factory=list)
    tasks: list[TaskItem] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.calendar or self.feeds or self.tasks)


DAILY_BRIEFING_SYSTEM_PROMPT = (
    "You are the user's daily-briefing agent. You run once each morning. Your job "
    "is to turn the pre-gathered context below into ONE tight, scannable morning "
    "briefing and deliver it — do not describe what you would do, take the actions.\n\n"
    "PROCESS (use your tools, do not narrate):\n"
    "1. Read the pre-gathered calendar and task context provided in the user "
    "message. That draft is your starting point — trust it for times and titles.\n"
    "2. Enrich feeds: if a Miniflux (or similar RSS) integration is configured, "
    "call api_call to fetch the latest unread entries and fold the 3-5 most "
    "notable into the briefing. If none is configured, skip feeds silently.\n"
    "3. Compose the briefing: lead with calendar (group by importance — critical/"
    "high first, skip low unless relevant), then open tasks/reminders due today, "
    "then a short 'Worth a look' feeds section. Keep the whole thing under ~1500 "
    "characters. No raw data dumps, no preamble like 'Here is your briefing'.\n"
    "4. Deliver: send the briefing as a push notification via the ntfy integration "
    "(api_call, POST to the user's configured topic, Title 'Daily Briefing'). The "
    "same text is also posted to the session automatically.\n"
    "5. Write facts back: call manage_memory (action=add) for any DURABLE fact "
    "worth remembering long-term (a new recurring commitment, a deadline, a "
    "person/context you inferred). Do NOT store the whole briefing — only crisp, "
    "reusable facts. One memory per fact.\n\n"
    "TONE: concise, warm, a little dry. English by default. If there is genuinely "
    "nothing scheduled and no notable news, say so in one line rather than padding."
)


def _fmt_calendar(item: CalendarItem) -> str:
    glyph = _IMPORTANCE_GLYPH.get(item.importance, "")
    parts = [f"{glyph}{item.when} — {item.title}".rstrip()]
    tail: list[str] = []
    if item.location:
        tail.append(f"@ {item.location}")
    if item.kind:
        tail.append(f"({item.kind})")
    if tail:
        parts.append(" ".join(tail))
    return "  " + " ".join(parts)


def _fmt_task(item: TaskItem) -> str:
    flag = "[!] " if item.priority == "high" else ""
    due = f" (due {item.due})" if item.due else ""
    return f"  {flag}{item.title}{due}"


def _fmt_feed(item: FeedItem) -> str:
    return f"  {item.title} — {item.source}"


def _render_section(title: str, lines: list[str], total: int, max_items: int) -> list[str]:
    """Render one section: a header carrying the *total* count, up to
    ``max_items`` body lines, and a trailing '…and N more' when capped."""
    if total == 0:
        return []
    out = [f"{title} ({total})"]
    shown = lines[:max_items]
    out.extend(shown)
    remaining = total - len(shown)
    if remaining > 0:
        out.append(f"  …and {remaining} more")
    return out


def compose_briefing(
    context: BriefingContext,
    *,
    max_items_per_section: int = 6,
    max_total_chars: int = 1800,
) -> str:
    """Render ``context`` into a bounded, item-covering briefing string.

    Args:
        context: The gathered calendar/feeds/tasks for the day.
        max_items_per_section: Max body lines shown per section (overflow is
            summarised as '…and N more', so the count still covers every item).
        max_total_chars: Hard ceiling on the returned string length.

    Returns:
        A markdown-ish briefing. Never exceeds ``max_total_chars`` characters.

    Raises:
        ValueError: If bounds are non-positive.
    """
    if max_items_per_section <= 0:
        raise ValueError("max_items_per_section must be > 0")
    if max_total_chars <= 0:
        raise ValueError("max_total_chars must be > 0")

    header = f"Daily Briefing — {context.date_label}"
    if context.is_empty():
        body = f"{header}\n\nNothing scheduled and no notable news. Enjoy the quiet."
        return body[:max_total_chars]

    lines: list[str] = [header, ""]

    cal_sorted = sorted(
        context.calendar,
        key=lambda c: (-_IMPORTANCE_RANK.get(c.importance, 1), c.when),
    )
    lines += _render_section(
        "Calendar", [_fmt_calendar(c) for c in cal_sorted],
        len(context.calendar), max_items_per_section,
    )

    task_open = [t for t in context.tasks]
    task_sorted = sorted(
        task_open, key=lambda t: (-_PRIORITY_RANK.get(t.priority, 1), t.title),
    )
    task_lines = _render_section(
        "Tasks", [_fmt_task(t) for t in task_sorted],
        len(task_open), max_items_per_section,
    )
    if task_lines:
        lines.append("")
        lines += task_lines

    feed_lines = _render_section(
        "Worth a look", [_fmt_feed(f) for f in context.feeds],
        len(context.feeds), max_items_per_section,
    )
    if feed_lines:
        lines.append("")
        lines += feed_lines

    return _bound("\n".join(lines), max_total_chars)


def _bound(text: str, limit: int) -> str:
    """Truncate ``text`` to ``limit`` chars on a line boundary when possible,
    appending a clear marker. Guarantees ``len(result) <= limit``."""
    if len(text) <= limit:
        return text
    marker = "\n…(truncated)"
    budget = max(0, limit - len(marker))
    clipped = text[:budget]
    nl = clipped.rfind("\n")
    if nl > budget // 2:
        clipped = clipped[:nl]
    return (clipped + marker)[:limit]


def gather_briefing_context(owner: str, db, *, now: datetime | None = None) -> BriefingContext:
    """Assemble a :class:`BriefingContext` from the DB for ``owner``.

    Reads today's calendar events (owner-scoped via the calendar join) and the
    owner's active schedule-triggered reminders due in the next 24h. RSS/feed
    items are intentionally left empty here — the live task lets the agent fetch
    them from Miniflux — but the returned context fully supports them.

    Defensive by design: any query failure yields an empty lane, never an
    exception, so the briefing task degrades gracefully.
    """
    from datetime import timedelta, timezone as _tz

    now = now or datetime.now(_tz.utc).replace(tzinfo=None)
    horizon = now + timedelta(days=1)
    date_label = now.strftime("%A, %B %d %Y")

    calendar = _gather_calendar(owner, db, now, horizon)
    tasks = _gather_tasks(owner, db, now, horizon)
    return BriefingContext(date_label=date_label, calendar=calendar, tasks=tasks)


def _gather_calendar(owner: str, db, start: datetime, end: datetime) -> list[CalendarItem]:
    try:
        from core.database import CalendarEvent as _CE, CalendarCal as _CC
        rows = (
            db.query(_CE)
            .join(_CC, _CE.calendar_id == _CC.id)
            .filter(
                _CC.owner == owner,
                _CE.dtstart >= start,
                _CE.dtstart <= end,
                _CE.status != "cancelled",
            )
            .order_by(_CE.dtstart)
            .all()
        )
    except Exception:
        return []
    return [
        CalendarItem(
            title=(r.summary or "(untitled)").strip(),
            when=r.dtstart.strftime("%H:%M") if not r.all_day else "all-day",
            importance=(r.importance or "normal"),
            location=(r.location or None),
            kind=(r.event_type or None),
        )
        for r in rows
    ]


def _gather_tasks(owner: str, db, start: datetime, end: datetime) -> list[TaskItem]:
    try:
        from core.database import ScheduledTask as _ST
        rows = (
            db.query(_ST)
            .filter(
                _ST.owner == owner,
                _ST.status == "active",
                _ST.trigger_type == "schedule",
                _ST.next_run != None,  # noqa: E711
                _ST.next_run >= start,
                _ST.next_run <= end,
            )
            .order_by(_ST.next_run)
            .all()
        )
    except Exception:
        return []
    return [
        TaskItem(
            title=(r.name or "Untitled Task").strip(),
            due=r.next_run.strftime("%H:%M") if r.next_run else None,
        )
        for r in rows
    ]
