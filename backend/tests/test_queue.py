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


def test_due_schedule_is_enqueued_once_and_next_run_is_advanced(monkeypatch):
    from datetime import timedelta
    from uuid import uuid4

    import app.queue as queue
    from app.models import WorkflowRun

    now = datetime.now(timezone.utc)
    schedule = type("Schedule", (), {
        "enabled": True,
        "next_run_at": now - timedelta(seconds=1),
        "timezone": "UTC",
        "cron_expression": "* * * * *",
        "workflow_id": uuid4(),
        "last_run_at": None,
    })()
    version = type("Version", (), {"graph": {"name": "scheduled demo", "nodes": [], "edges": []}})()

    class Rows:
        def all(self):
            return [schedule]

    class Session:
        def __init__(self):
            self.added = []
            self.committed = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def scalars(self, _statement):
            return Rows()

        def scalar(self, _statement):
            return version

        def add(self, item):
            self.added.append(item)

        def commit(self):
            self.committed = True

    session = Session()
    monkeypatch.setattr(queue, "SessionLocal", lambda: session)

    count = queue.enqueue_due_schedules()

    assert count == 1
    assert session.committed is True
    assert schedule.next_run_at > now
    assert schedule.last_run_at is not None
    runs = [item for item in session.added if isinstance(item, WorkflowRun)]
    assert len(runs) == 1
    assert runs[0].status == "queued"
    assert runs[0].source == "schedule"
    assert runs[0].graph_snapshot == version.graph


def test_due_schedule_with_missing_version_is_disabled(monkeypatch):
    from datetime import timedelta

    import app.queue as queue

    schedule = type("Schedule", (), {
        "enabled": True,
        "next_run_at": datetime.now(timezone.utc) - timedelta(seconds=1),
        "timezone": "UTC",
        "cron_expression": "* * * * *",
        "workflow_id": None,
        "last_run_at": None,
    })()

    class Rows:
        def all(self):
            return [schedule]

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def scalars(self, _statement):
            return Rows()

        def scalar(self, _statement):
            return None

        def add(self, _item):
            raise AssertionError("No run should be created without a saved workflow version")

        def commit(self):
            self.committed = True

    session = Session()
    monkeypatch.setattr(queue, "SessionLocal", lambda: session)

    assert queue.enqueue_due_schedules() == 0
    assert schedule.enabled is False
    assert schedule.next_run_at is None
    assert session.committed is True



def _sqlite_queue_session(monkeypatch):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    import app.queue as queue
    from app.db import Base
    import app.models  # noqa: F401

    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(queue, "SessionLocal", factory)
    return engine, factory


def test_claim_recovers_stale_running_run_without_heartbeat(monkeypatch):
    from datetime import timedelta
    from app.models import WorkflowRun
    from app.queue import claim_next_run

    engine, factory = _sqlite_queue_session(monkeypatch)
    try:
        stale_started = datetime.now(timezone.utc) - timedelta(minutes=5)
        with factory() as session:
            run = WorkflowRun(
                status="running",
                source="ui",
                graph_snapshot={"nodes": [], "edges": []},
                started_at=stale_started,
                heartbeat_at=None,
                locked_by="dead-worker",
            )
            session.add(run)
            session.commit()
            run_id = str(run.id)

        claimed_id = claim_next_run("replacement-worker")

        assert claimed_id == run_id
        with factory() as session:
            recovered = session.get(WorkflowRun, run.id)
            assert recovered.status == "running"
            assert recovered.locked_by == "replacement-worker"
            assert recovered.heartbeat_at is not None
            assert recovered.started_at.replace(tzinfo=timezone.utc) > stale_started
    finally:
        engine.dispose()


def test_claim_finalizes_stale_cancellation_without_heartbeat(monkeypatch):
    from datetime import timedelta
    from app.models import WorkflowRun
    from app.queue import claim_next_run

    engine, factory = _sqlite_queue_session(monkeypatch)
    try:
        stale_started = datetime.now(timezone.utc) - timedelta(minutes=5)
        with factory() as session:
            run = WorkflowRun(
                status="cancelling",
                source="ui",
                graph_snapshot={"nodes": [], "edges": []},
                started_at=stale_started,
                heartbeat_at=None,
                locked_by="dead-worker",
            )
            session.add(run)
            session.commit()
            run_id = run.id

        assert claim_next_run("replacement-worker") is None
        with factory() as session:
            finalized = session.get(WorkflowRun, run_id)
            assert finalized.status == "cancelled"
            assert finalized.finished_at is not None
            assert finalized.locked_by is None
            assert finalized.heartbeat_at is None
            assert finalized.error == "Cancellation finalized after worker heartbeat expired"
    finally:
        engine.dispose()


def _run_process_and_capture_cancel(monkeypatch, mutate_run=None, fail_status_read=False):
    from app.models import WorkflowRun
    import app.queue as queue

    engine, factory = _sqlite_queue_session(monkeypatch)
    worker_id = "original-worker"
    with factory() as session:
        run = WorkflowRun(
            status="running",
            source="ui",
            graph_snapshot={"name": "lease test", "nodes": [], "edges": []},
            locked_by=worker_id,
            started_at=datetime.now(timezone.utc),
            heartbeat_at=datetime.now(timezone.utc),
        )
        session.add(run)
        session.commit()
        run_id = str(run.id)

    observed = {}
    real_session_local = queue.SessionLocal
    session_calls = {"count": 0}

    if fail_status_read:
        def session_local_with_transient_failure():
            session_calls["count"] += 1
            if session_calls["count"] == 2:
                raise RuntimeError("temporary database failure")
            return real_session_local()
        monkeypatch.setattr(queue, "SessionLocal", session_local_with_transient_failure)

    def fake_execute_graph(_graph, _registry, **kwargs):
        if mutate_run is not None:
            with factory() as session:
                current = session.get(WorkflowRun, run.id)
                mutate_run(current)
                session.commit()
        try:
            observed["cancel"] = kwargs["should_cancel"]()
        except Exception as exc:
            observed["exception"] = exc
            # execute_graph deliberately ignores transient callback errors.
        return {"status": "completed", "outputs": {}}

    monkeypatch.setattr(queue, "execute_graph", fake_execute_graph)
    try:
        queue.process_run(run_id, worker_id)
        with factory() as session:
            final_run = session.get(WorkflowRun, run.id)
            observed["final_status"] = final_run.status
            observed["final_owner"] = final_run.locked_by
        return observed
    finally:
        engine.dispose()


def test_process_run_stops_when_lease_owner_changes(monkeypatch):
    def change_owner(run):
        run.locked_by = "replacement-worker"

    observed = _run_process_and_capture_cancel(monkeypatch, change_owner)

    assert observed["cancel"] is True
    assert observed["final_status"] == "running"
    assert observed["final_owner"] == "replacement-worker"


def test_process_run_stops_when_run_is_cancelled(monkeypatch):
    def request_cancellation(run):
        run.status = "cancelling"

    observed = _run_process_and_capture_cancel(monkeypatch, request_cancellation)

    assert observed["cancel"] is True
    assert observed["final_status"] == "cancelled"
    assert observed["final_owner"] is None


def test_process_run_continues_while_worker_owns_lease(monkeypatch):
    observed = _run_process_and_capture_cancel(monkeypatch)

    assert observed["cancel"] is False
    assert observed["final_status"] == "completed"
    assert observed["final_owner"] is None


def test_process_run_does_not_treat_transient_database_error_as_cancellation(monkeypatch):
    from app.models import WorkflowRun
    import app.queue as queue

    engine, factory = _sqlite_queue_session(monkeypatch)
    worker_id = "original-worker"

    with factory() as session:
        run = WorkflowRun(
            status="running",
            source="ui",
            graph_snapshot={
                "name": "transient lease read test",
                "nodes": [{"id": "manual", "type": "trigger.manual"}],
                "edges": [],
            },
            locked_by=worker_id,
            started_at=datetime.now(timezone.utc),
            heartbeat_at=datetime.now(timezone.utc),
        )
        session.add(run)
        session.commit()
        run_id = str(run.id)

    real_session_local = queue.SessionLocal
    session_calls = {"count": 0}

    def session_local_with_transient_failure():
        session_calls["count"] += 1
        if session_calls["count"] == 2:
            raise RuntimeError("temporary database failure")
        return real_session_local()

    monkeypatch.setattr(queue, "SessionLocal", session_local_with_transient_failure)

    try:
        queue.process_run(run_id, worker_id)

        with factory() as session:
            final_run = session.get(WorkflowRun, run.id)
            assert final_run.status == "completed"
            assert final_run.result["outputs"]["manual"]["status"] == "completed"

        assert session_calls["count"] >= 3
    finally:
        engine.dispose()
