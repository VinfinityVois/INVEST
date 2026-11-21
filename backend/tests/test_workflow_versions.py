from sqlalchemy.dialects import postgresql

from app.main import _lock_workflow_for_version_write


def test_version_write_lookup_locks_workflow_row():
    class FakeSession:
        statement = None

        def scalar(self, statement):
            self.statement = statement
            return "workflow"

    session = FakeSession()
    assert _lock_workflow_for_version_write(session, "workflow-id") == "workflow"

    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql
    assert "workflows" in sql



def test_run_state_transition_lookup_locks_run_row():
    from app.main import _lock_run_for_update

    class FakeSession:
        statement = None

        def scalar(self, statement):
            self.statement = statement
            return "run"

    session = FakeSession()
    assert _lock_run_for_update(session, "run-id") == "run"

    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql
    assert "runs" in sql



def test_schedule_mutation_lookup_locks_schedule_row():
    from app.main import _lock_schedule_for_update

    class FakeSession:
        statement = None

        def scalar(self, statement):
            self.statement = statement
            return "schedule"

    session = FakeSession()
    assert _lock_schedule_for_update(session, "workflow-id", "schedule-id") == "schedule"

    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "FOR UPDATE" in sql
    assert "workflow_schedules" in sql


def test_finding_risk_expiry_requires_timezone_and_future_date():
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    import pytest
    from fastapi import HTTPException
    from app.main import FindingStateUpdate, update_finding_state

    workflow_id = uuid4()
    with pytest.raises(HTTPException) as naive_error:
        update_finding_state(
            workflow_id,
            "fingerprint",
            FindingStateUpdate(
                state="accepted_risk",
                reason="Temporary exception",
                expires_at=datetime(2030, 1, 1),
            ),
            None,
        )
    assert naive_error.value.status_code == 422

    with pytest.raises(HTTPException) as past_error:
        update_finding_state(
            workflow_id,
            "fingerprint",
            FindingStateUpdate(
                state="accepted_risk",
                reason="Temporary exception",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            ),
            None,
        )
    assert past_error.value.status_code == 422


def test_listing_finding_states_expires_risk_and_writes_audit(monkeypatch):
    from datetime import datetime, timedelta, timezone
    from uuid import uuid4

    from app import main

    workflow_id = uuid4()
    expired = type("State", (), {
        "fingerprint": "expired-fingerprint",
        "state": "accepted_risk",
        "reason": "Temporary exception",
        "expires_at": datetime.now(timezone.utc) - timedelta(seconds=1),
    })()
    active = type("State", (), {
        "fingerprint": "active-fingerprint",
        "state": "accepted_risk",
        "reason": "Still approved",
        "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
    })()

    class Rows:
        def all(self):
            return [expired, active]

    class FakeSession:
        added = []
        committed = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def scalars(self, statement):
            return Rows()

        def add(self, item):
            self.added.append(item)

        def commit(self):
            self.committed = True

    session = FakeSession()
    monkeypatch.setattr(main, "SessionLocal", lambda: session)
    monkeypatch.setattr(main, "_workflow_in_active_workspace", lambda _session, _request, _id, **kwargs: object())
    monkeypatch.setattr(main, "_lock_workflow_for_version_write", lambda _session, _id: object())

    result = main.list_finding_states(workflow_id, None)

    assert result[0]["state"] == "open"
    assert result[0]["expires_at"] is None
    assert result[0]["reason"] == "Срок принятого риска истёк."
    assert result[1]["state"] == "accepted_risk"
    assert result[1]["expires_at"] == active.expires_at
    assert session.committed is True
    assert len(session.added) == 1
    assert session.added[0].action == "finding.state.expired"
    assert session.added[0].details["previous_state"] == "accepted_risk"



def test_finding_state_history_query_is_bounded():
    from uuid import uuid4

    from app.main import finding_state_history

    workflow_id = uuid4()
    class FakeSession:
        statement = None

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def get(self, model, identifier):
            return object()

        def scalars(self, statement):
            self.statement = statement
            class Rows:
                def all(self):
                    return []
            return Rows()

    session = FakeSession()
    from app import main
    original = main.SessionLocal
    main.SessionLocal = lambda: session
    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr(main, "_workflow_in_active_workspace", lambda _session, _request, _id, **kwargs: object())
    try:
        assert finding_state_history(workflow_id, "a" * 64, None, limit=25, offset=50) == []
    finally:
        main.SessionLocal = original
        monkeypatch.undo()

    sql = str(session.statement.compile(dialect=postgresql.dialect()))
    assert "LIMIT" in sql
    assert 25 in session.statement.compile(dialect=postgresql.dialect()).params.values()
    assert 50 in session.statement.compile(dialect=postgresql.dialect()).params.values()
    assert "ORDER BY" in sql
