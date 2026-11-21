from sqlalchemy import create_engine, inspect

from app.db import Base
import app.models  # noqa: F401


def test_all_persisted_models_create_on_sqlite():
    engine = create_engine("sqlite:///:memory:")
    try:
        Base.metadata.create_all(engine)
        tables = set(inspect(engine).get_table_names())
        assert {
            "workflows",
            "workflow_versions",
            "runs",
            "findings",
            "finding_states",
            "credentials",
            "audit_log",
            "projects",
            "workflow_schedules",
            "workflow_templates",
            "users",
            "user_sessions",
            "login_rate_limits",
        }.issubset(tables)
    finally:
        engine.dispose()


