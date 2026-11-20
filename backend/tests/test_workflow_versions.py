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
