import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import User
from app.security.auth import authenticate_user, normalize_email
from app.security.passwords import hash_password


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
        email="auth@example.test",
        password_hash=hash_password("CorrectPassword123!"),
        is_active=True,
    )
    db.add(item)
    db.flush()
    return item


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("USER@example.test", "user@example.test"),
        ("  User@Example.Test  ", "user@example.test"),
        ("user@example.test", "user@example.test"),
    ],
)
def test_normalize_email(value, expected):
    assert normalize_email(value) == expected


@pytest.mark.parametrize("value", ["", "   ", "x" * 321, None, 123])
def test_normalize_email_rejects_invalid_values(value):
    with pytest.raises(ValueError):
        normalize_email(value)


def test_authenticate_user_accepts_normalized_email(db, user):
    result = authenticate_user(
        db,
        "  AUTH@EXAMPLE.TEST ",
        "CorrectPassword123!",
    )

    assert result is not None
    assert result.id == user.id


def test_authenticate_user_rejects_wrong_password(db, user):
    assert authenticate_user(
        db,
        user.email,
        "WrongPassword123!",
    ) is None


def test_authenticate_user_rejects_unknown_email(db):
    assert authenticate_user(
        db,
        "missing@example.test",
        "CorrectPassword123!",
    ) is None


def test_authenticate_user_rejects_inactive_user(db, user):
    user.is_active = False
    db.flush()

    assert authenticate_user(
        db,
        user.email,
        "CorrectPassword123!",
    ) is None


@pytest.mark.parametrize(
    ("email", "password"),
    [
        (None, "CorrectPassword123!"),
        ("auth@example.test", None),
        ("auth@example.test", ""),
        ("invalid-email", "CorrectPassword123!"),
    ],
)
def test_authenticate_user_rejects_invalid_input(db, email, password):
    assert authenticate_user(db, email, password) is None
