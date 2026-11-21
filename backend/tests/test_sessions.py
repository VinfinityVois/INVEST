import hashlib
import uuid
from datetime import timedelta, timezone, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import User, UserSession
from app.security.sessions import (
    create_session,
    get_user_for_session,
    revoke_session,
)


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestingSession() as session:
        yield session

    engine.dispose()


@pytest.fixture
def user(db):
    item = User(
        id=uuid.uuid4(),
        email="sessions@example.test",
        password_hash="test-hash",
        is_active=True,
    )
    db.add(item)
    db.flush()
    return item


def test_create_session_stores_only_token_hash(db, user):
    token, session = create_session(db, user.id)

    assert isinstance(token, str)
    assert len(token) >= 40
    assert session.user_id == user.id
    assert session.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert session.token_hash != token
    assert session.expires_at > datetime.now(timezone.utc)
    assert session.last_seen_at is not None


def test_create_session_generates_unique_tokens(db, user):
    token1, _ = create_session(db, user.id)
    token2, _ = create_session(db, user.id)

    assert token1 != token2


@pytest.mark.parametrize(
    "lifetime",
    [timedelta(0), timedelta(seconds=-1)],
)
def test_create_session_rejects_non_positive_lifetime(db, user, lifetime):
    with pytest.raises(ValueError):
        create_session(db, user.id, lifetime=lifetime)


def test_create_session_rejects_missing_user(db):
    with pytest.raises(ValueError):
        create_session(db, uuid.uuid4())


def test_create_session_rejects_inactive_user(db):
    inactive = User(
        id=uuid.uuid4(),
        email="inactive@example.test",
        password_hash="test-hash",
        is_active=False,
    )
    db.add(inactive)
    db.flush()

    with pytest.raises(ValueError):
        create_session(db, inactive.id)


def test_get_user_for_valid_session(db, user):
    token, _ = create_session(db, user.id)

    found = get_user_for_session(db, token)

    assert found is not None
    assert found.id == user.id


@pytest.mark.parametrize("token", [None, "", "invalid-token"])
def test_get_user_for_invalid_token_returns_none(db, token):
    assert get_user_for_session(db, token) is None


def test_get_user_rejects_expired_session(db, user):
    token, session = create_session(db, user.id)
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.flush()

    assert get_user_for_session(db, token) is None


def test_get_user_rejects_revoked_session(db, user):
    token, _ = create_session(db, user.id)

    assert revoke_session(db, token) is True
    assert get_user_for_session(db, token) is None


def test_get_user_rejects_inactive_user(db, user):
    token, _ = create_session(db, user.id)
    user.is_active = False
    db.flush()

    assert get_user_for_session(db, token) is None


def test_revoke_session_is_idempotent(db, user):
    token, _ = create_session(db, user.id)

    assert revoke_session(db, token) is True
    assert revoke_session(db, token) is False


def test_revoke_unknown_token_returns_false(db):
    assert revoke_session(db, "unknown-token") is False


def test_revoke_does_not_store_raw_token(db, user):
    token, _ = create_session(db, user.id)

    revoke_session(db, token)

    stored = db.query(UserSession).one()
    assert stored.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert stored.revoked_at is not None
