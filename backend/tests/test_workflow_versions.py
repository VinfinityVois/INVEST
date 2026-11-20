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
        )
    assert past_error.value.status_code == 422
