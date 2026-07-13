"""Tests for the daily-briefing composer and the seeded daily-briefing task.

The composer tests use synthetic inputs only (no DB / network). The seeded-task
test validates the HOUSEKEEPING_DEFAULTS entry: cron parses and ship_paused is
true so the task never auto-fires until the user enables it.
"""

import pytest

from src.briefing_composer import (
    BriefingContext,
    CalendarItem,
    FeedItem,
    TaskItem,
    compose_briefing,
    DAILY_BRIEFING_SYSTEM_PROMPT,
)


def _synthetic_context():
    return BriefingContext(
        date_label="Monday, July 13 2026",
        calendar=[
            CalendarItem("Standup", "09:30", importance="normal", kind="work"),
            CalendarItem("Dentist", "14:00", importance="high", location="Clinic"),
            CalendarItem("Flight to NYC", "18:15", importance="critical", kind="travel"),
        ],
        feeds=[
            FeedItem("Rust 2.0 released", "Hacker News"),
            FeedItem("Local election results", "AP"),
        ],
        tasks=[
            TaskItem("Renew passport", due="10:00", priority="high"),
            TaskItem("Water plants", priority="low"),
        ],
    )


def test_compose_briefing_covers_every_item_when_under_caps():
    ctx = _synthetic_context()

    briefing = compose_briefing(ctx, max_items_per_section=6, max_total_chars=2000)

    # Every calendar, feed, and task title must appear verbatim.
    for item in ctx.calendar:
        assert item.title in briefing
    for item in ctx.feeds:
        assert item.title in briefing
    for item in ctx.tasks:
        assert item.title in briefing
    # Section headers carry the total counts.
    assert "Calendar (3)" in briefing
    assert "Tasks (2)" in briefing
    assert "Worth a look (2)" in briefing


def test_compose_briefing_is_bounded():
    # 200 items per lane, long titles — output must still respect the ceiling.
    ctx = BriefingContext(
        date_label="Tuesday, July 14 2026",
        calendar=[CalendarItem(f"Event number {i} " * 5, "08:00") for i in range(200)],
        feeds=[FeedItem(f"Headline {i} " * 5, "Feed") for i in range(200)],
        tasks=[TaskItem(f"Task {i} " * 5) for i in range(200)],
    )

    briefing = compose_briefing(ctx, max_items_per_section=6, max_total_chars=1800)

    assert len(briefing) <= 1800


def test_compose_briefing_overflow_reports_remaining_count():
    ctx = BriefingContext(
        date_label="Wed",
        calendar=[CalendarItem(f"E{i}", "08:00") for i in range(10)],
    )

    briefing = compose_briefing(ctx, max_items_per_section=4, max_total_chars=2000)

    # Header count covers all 10; body shows 4 and accounts for the other 6.
    assert "Calendar (10)" in briefing
    assert "…and 6 more" in briefing


def test_compose_briefing_orders_calendar_by_importance():
    ctx = BriefingContext(
        date_label="Thu",
        calendar=[
            CalendarItem("Low thing", "07:00", importance="low"),
            CalendarItem("Critical thing", "20:00", importance="critical"),
        ],
    )

    briefing = compose_briefing(ctx)

    assert briefing.index("Critical thing") < briefing.index("Low thing")


def test_compose_briefing_empty_context_is_quiet_and_bounded():
    ctx = BriefingContext(date_label="Fri")

    briefing = compose_briefing(ctx, max_total_chars=200)

    assert "Nothing scheduled" in briefing
    assert len(briefing) <= 200


def test_compose_briefing_rejects_bad_bounds():
    ctx = BriefingContext(date_label="Sat")
    with pytest.raises(ValueError):
        compose_briefing(ctx, max_items_per_section=0)
    with pytest.raises(ValueError):
        compose_briefing(ctx, max_total_chars=0)


def test_system_prompt_mentions_delivery_and_memory():
    # The briefing prompt must drive ntfy delivery + memory write-back.
    assert "ntfy" in DAILY_BRIEFING_SYSTEM_PROMPT
    assert "manage_memory" in DAILY_BRIEFING_SYSTEM_PROMPT


def test_seeded_daily_briefing_task_validates():
    from croniter import croniter
    from src.task_scheduler import HOUSEKEEPING_DEFAULTS

    defs = HOUSEKEEPING_DEFAULTS["daily_briefing"]

    assert defs["task_type"] == "llm"
    assert defs["ship_paused"] is True
    assert defs["schedule"] == "cron"
    assert (defs.get("prompt") or "").strip()
    # Cron must parse and be the ~06:30 morning slot.
    assert croniter.is_valid(defs["cron_expression"])
    assert defs["cron_expression"] == "30 6 * * *"
