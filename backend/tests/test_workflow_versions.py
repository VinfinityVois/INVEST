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
