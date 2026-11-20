"""Durable cron scheduling for saved workflows."""
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
from croniter import croniter
from sqlalchemy import select
from app.db import SessionLocal
from app.models import WorkflowRun, WorkflowSchedule, WorkflowVersion


def next_run_time(expression: str, timezone_name: str, after: datetime | None = None) -> datetime:
    if not isinstance(expression, str) or len(expression) > 120 or not croniter.is_valid(expression):
        raise ValueError("Некорректное cron-выражение (ожидается 5 полей).")
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, TypeError, ValueError) as exc:
        raise ValueError("Неизвестный часовой пояс IANA.") from exc
    base = after or datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    occurrence = croniter(expression, base.astimezone(zone)).get_next(datetime)
    if occurrence.tzinfo is None:
        occurrence = occurrence.replace(tzinfo=zone)
    return occurrence.astimezone(timezone.utc)


def enqueue_due_schedules(now: datetime | None = None, limit: int = 50) -> int:
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    current = current.astimezone(timezone.utc)
    created = 0
    with SessionLocal() as session:
        due = session.scalars(
            select(WorkflowSchedule)
            .where(WorkflowSchedule.enabled.is_(True), WorkflowSchedule.next_run_at <= current)
            .order_by(WorkflowSchedule.next_run_at, WorkflowSchedule.id)
            .with_for_update(skip_locked=True).limit(max(1, min(limit, 200)))
        ).all()
        for schedule in due:
            version = session.scalar(
                select(WorkflowVersion).where(WorkflowVersion.workflow_id == schedule.workflow_id)
                .order_by(WorkflowVersion.version.desc()).limit(1)
            )
            if version is None:
                schedule.enabled = False
                continue
            run = WorkflowRun(workflow_id=schedule.workflow_id, status="queued",
                              source="schedule", graph_snapshot=version.graph)
            session.add(run)
            session.flush()
            schedule.last_run_at = current
            schedule.last_run_id = run.id
            # Coalesce downtime into one run; never replay a backlog of missed ticks.
            schedule.next_run_at = next_run_time(schedule.cron_expression, schedule.timezone, current)
            created += 1
        session.commit()
    return created
