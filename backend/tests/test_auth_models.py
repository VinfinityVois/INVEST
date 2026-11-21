import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, event, inspect, select, func
from sqlalchemy.exc import IntegrityError

from app.db import Base
from app.models import User, UserSession  # noqa: F401


@pytest.fixture
def engine():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


def _insert_user(connection, email):
    user_id = uuid.uuid4()
    connection.execute(
        User.__table__.insert().values(
            id=user_id,
            email=email,
            password_hash="test-hash",
        )
    )
    return user_id


def test_user_email_is_unique(engine):
    with engine.begin() as connection:
        _insert_user(connection, "admin@example.test")

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            _insert_user(connection, "admin@example.test")


def test_session_token_hash_is_unique(engine):
    with engine.begin() as connection:
        user_id = _insert_user(connection, "user@example.test")
        session_values = {
            "user_id": user_id,
            "token_hash": "a" * 64,
            "expires_at": datetime.now(timezone.utc) + timedelta(days=1),
        }
        connection.execute(UserSession.__table__.insert().values(**session_values))

    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                UserSession.__table__.insert().values(**session_values)
            )


def test_deleting_user_cascades_to_sessions(engine):
    with engine.begin() as connection:
        user_id = _insert_user(connection, "cascade@example.test")
        connection.execute(
            UserSession.__table__.insert().values(
                user_id=user_id,
                token_hash="b" * 64,
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
        )

    with engine.begin() as connection:
        connection.execute(
            User.__table__.delete().where(User.id == user_id)
        )

    with engine.connect() as connection:
        count = connection.execute(
            select(func.count()).select_from(UserSession.__table__)
        ).scalar_one()

    assert count == 0


def test_session_indexes_and_foreign_key(engine):
    inspector = inspect(engine)

    indexes = {
        index["name"]
        for index in inspector.get_indexes("user_sessions")
    }
    assert "ix_user_sessions_user_id" in indexes
    assert "ix_user_sessions_expires_at" in indexes

    foreign_keys = inspector.get_foreign_keys("user_sessions")
    assert any(
        fk["referred_table"] == "users"
        and fk["constrained_columns"] == ["user_id"]
        and fk["options"].get("ondelete") == "CASCADE"
        for fk in foreign_keys
    )

def test_user_email_must_be_lowercase(engine):
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            _insert_user(connection, "Admin@example.test")