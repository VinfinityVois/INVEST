"""Cron/timezone utilities for workflow scheduling."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from croniter import croniter


def next_run_time(
    expression: str,
    timezone_name: str,
    after: datetime | None = None,
) -> datetime:
    """Return the next cron occurrence as an aware UTC datetime."""
    if (
        not isinstance(expression, str)
        or not expression.strip()
        or len(expression) > 120
        or len(expression.split()) != 5
        or not croniter.is_valid(expression)
    ):
        raise ValueError("Invalid cron expression; expected five fields.")

    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, TypeError, ValueError) as exc:
        raise ValueError("Unknown IANA timezone.") from exc

    base = after or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)

    occurrence = croniter(
        expression,
        base.astimezone(zone),
    ).get_next(datetime)

    if occurrence.tzinfo is None:
        occurrence = occurrence.replace(tzinfo=zone)

    return occurrence.astimezone(timezone.utc)
