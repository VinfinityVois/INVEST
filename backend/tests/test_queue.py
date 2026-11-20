from datetime import datetime, timezone

import pytest

from app.queue import _findings_from_result, _next_schedule_at, make_worker_id


def test_queue_deduplicates_findings_by_fingerprint():
    result = {
        "outputs": {
            "secrets": {
                "findings": [
                    {"fingerprint": "same", "rule_id": "SECRET_A"},
                    {"fingerprint": "unique", "rule_id": "SECRET_B"},
                ]
            },
            "merge": {
                "findings": [
                    {"fingerprint": "same", "rule_id": "SECRET_A"},
                    {"rule_id": "NO_FINGERPRINT"},
                ]
            },
        }
    }

    findings = _findings_from_result(result)

    assert [item["fingerprint"] for item in findings] == ["same", "unique"]


def test_worker_id_is_non_empty_and_unique():
    first = make_worker_id()
    second = make_worker_id()

    assert first
    assert first != second



def test_cron_schedule_computes_next_occurrence_in_timezone():
    base = datetime(2026, 11, 21, 10, 2, tzinfo=timezone.utc)

    next_run = _next_schedule_at("*/5 * * * *", "Europe/Amsterdam", base)

    assert next_run == datetime(2026, 11, 21, 10, 5, tzinfo=timezone.utc)


def test_cron_schedule_rejects_unknown_timezone():
    with pytest.raises(Exception):
        _next_schedule_at("*/5 * * * *", "Mars/Olympus", datetime.now(timezone.utc))



def test_due_schedule_enqueues_one_regular_workflow_run(monkeypatch):
    from datetime import timedelta
    from types import SimpleNamespace

    import app.queue as queue
    from app.models import WorkflowRun

    now = datetime.now(timezone.utc)
    schedule = SimpleNamespace(
        id="schedule-id",
        workflow_id="workflow-id",
        cron_expression="*/5 * * * *",
        timezone="UTC",
        enabled=True,
        next_run_at=now - timedelta(seconds=1),
        last_run_at=None,
    )
    version = SimpleNamespace(graph={"name": "scheduled", "nodes": [], "edges": []})

    class Rows:
        def all(self):
            return [schedule]

    class FakeSession:
        def __init__(self):
            self.added = []

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def scalars(self, _query):
            return Rows()

        def scalar(self, _query):
            return version

        def add(self, item):
            self.added.append(item)

        def commit(self):
            pass

    fake = FakeSession()
    monkeypatch.setattr(queue, "SessionLocal", lambda: fake)

    count = queue.enqueue_due_schedules()

    assert count == 1
    runs = [item for item in fake.added if isinstance(item, WorkflowRun)]
    assert len(runs) == 1
    assert runs[0].source == "schedule"
    assert runs[0].status == "queued"
    assert runs[0].graph_snapshot == version.graph
    assert schedule.next_run_at > now
    assert schedule.last_run_at is not None
