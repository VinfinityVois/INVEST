from datetime import datetime, timezone
import pytest
from app.scheduler import next_run_time

def test_cron_next_run_respects_timezone():
    after = datetime(2026, 1, 1, 10, 1, tzinfo=timezone.utc)
    assert next_run_time("0 12 * * *", "Europe/Stockholm", after) == datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc)

def test_cron_rejects_invalid_expression():
    with pytest.raises(ValueError, match="cron"):
        next_run_time("not a cron", "UTC")

def test_cron_rejects_unknown_timezone():
    with pytest.raises(ValueError, match="часовой пояс"):
        next_run_time("0 12 * * *", "Mars/Olympus")

def test_cron_rejects_six_field_seconds_extension():
    with pytest.raises(ValueError, match="cron"):
        next_run_time("*/5 * * * * *", "UTC")


def test_cron_next_run_tracks_summer_daylight_saving_time():
    after = datetime(2026, 3, 28, 10, 0, tzinfo=timezone.utc)
    assert next_run_time("0 9 * * *", "Europe/Stockholm", after) == datetime(2026, 3, 29, 7, 0, tzinfo=timezone.utc)


def test_cron_next_run_tracks_winter_daylight_saving_time():
    after = datetime(2026, 10, 24, 10, 0, tzinfo=timezone.utc)
    assert next_run_time("0 9 * * *", "Europe/Stockholm", after) == datetime(2026, 10, 25, 8, 0, tzinfo=timezone.utc)


def test_enqueue_due_schedule_creates_run_and_advances_schedule(monkeypatch):
    from types import SimpleNamespace
    from uuid import uuid4
    from app import scheduler

    now = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    schedule = SimpleNamespace(
        id=uuid4(), workflow_id=uuid4(), enabled=True,
        next_run_at=now - __import__("datetime").timedelta(minutes=1),
        cron_expression="0 12 * * *", timezone="Europe/Stockholm",
        last_run_at=None, last_run_id=None,
    )
    graph = {"nodes": [{"id": "scan", "type": "scan"}], "edges": []}
    version = SimpleNamespace(graph=graph)

    class FakeSession:
        def __init__(self):
            self.added = []
            self.committed = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def scalars(self, statement):
            return SimpleNamespace(all=lambda: [schedule])
        def scalar(self, statement):
            return version
        def add(self, item):
            self.added.append(item)
        def flush(self):
            for item in self.added:
                if isinstance(item, scheduler.WorkflowRun) and item.id is None:
                    item.id = uuid4()
        def commit(self):
            self.committed = True

    fake = FakeSession()
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: fake)

    assert scheduler.enqueue_due_schedules(now=now) == 1
    run = next(item for item in fake.added if isinstance(item, scheduler.WorkflowRun))
    assert run.workflow_id == schedule.workflow_id
    assert run.status == "queued"
    assert run.source == "schedule"
    assert run.graph_snapshot == graph
    assert schedule.last_run_at == now
    assert schedule.last_run_id == run.id
    assert schedule.next_run_at == datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc)
    assert fake.committed


def test_enqueue_due_schedule_disables_orphaned_workflow(monkeypatch):
    from types import SimpleNamespace
    from uuid import uuid4
    from app import scheduler

    now = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    schedule = SimpleNamespace(
        id=uuid4(), workflow_id=uuid4(), enabled=True,
        next_run_at=now - __import__("datetime").timedelta(minutes=1),
        cron_expression="0 12 * * *", timezone="UTC",
        last_run_at=None, last_run_id=None,
    )

    class FakeSession:
        def __init__(self):
            self.added = []
            self.committed = False
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def scalars(self, statement):
            return SimpleNamespace(all=lambda: [schedule])
        def scalar(self, statement):
            return None
        def add(self, item):
            self.added.append(item)
        def commit(self):
            self.committed = True

    fake = FakeSession()
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: fake)

    assert scheduler.enqueue_due_schedules(now=now) == 0
    assert schedule.enabled is False
    assert fake.added == []
    assert fake.committed
