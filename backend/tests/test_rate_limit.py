import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import LoginRateLimit
from app.security.rate_limit import (
    LIMITS,
    WINDOW,
    cleanup_expired_rate_limits,
    clear_email_attempts,
    record_login_attempt,
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
def now():
    return datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)


def test_email_limit_allows_first_five_attempts(db, now):
    results = [
        record_login_attempt(db, "email", "user@example.test", now)
        for _ in range(5)
    ]

    assert all(result.allowed for result in results)
    assert results[-1].attempts == 5
    assert results[-1].limit == LIMITS["email"]


def test_email_limit_blocks_sixth_attempt(db, now):
    for _ in range(5):
        record_login_attempt(db, "email", "user@example.test", now)

    result = record_login_attempt(
        db,
        "email",
        "user@example.test",
        now,
    )

    assert result.allowed is False
    assert result.attempts == 6
    assert result.retry_after == int(WINDOW.total_seconds())


def test_ip_limit_blocks_after_thirty_attempts(db, now):
    for _ in range(30):
        result = record_login_attempt(db, "ip", "192.0.2.10", now)

    assert result.allowed is True
    assert result.attempts == 30

    blocked = record_login_attempt(
        db,
        "ip",
        "192.0.2.10",
        now,
    )

    assert blocked.allowed is False
    assert blocked.attempts == 31


def test_expired_window_starts_new_counter(db, now):
    first = record_login_attempt(
        db,
        "email",
        "user@example.test",
        now,
    )
    assert first.attempts == 1

    next_window = record_login_attempt(
        db,
        "email",
        "user@example.test",
        now + WINDOW + timedelta(seconds=1),
    )

    assert next_window.allowed is True
    assert next_window.attempts == 1


def test_window_does_not_reset_before_expiration(db, now):
    record_login_attempt(
        db,
        "email",
        "user@example.test",
        now,
    )

    result = record_login_attempt(
        db,
        "email",
        "user@example.test",
        now + WINDOW - timedelta(seconds=1),
    )

    assert result.attempts == 2


def test_email_counter_can_be_cleared_without_clearing_ip(db, now):
    record_login_attempt(db, "email", "user@example.test", now)
    record_login_attempt(db, "ip", "192.0.2.10", now)

    clear_email_attempts(db, "user@example.test")

    email_rows = db.execute(
        select(LoginRateLimit).where(LoginRateLimit.scope == "email")
    ).scalars().all()
    ip_rows = db.execute(
        select(LoginRateLimit).where(LoginRateLimit.scope == "ip")
    ).scalars().all()

    assert email_rows == []
    assert len(ip_rows) == 1


def test_different_keys_have_independent_counters(db, now):
    first = record_login_attempt(
        db,
        "email",
        "first@example.test",
        now,
    )
    second = record_login_attempt(
        db,
        "email",
        "second@example.test",
        now,
    )

    assert first.attempts == 1
    assert second.attempts == 1


def test_unsupported_scope_is_rejected(db, now):
    with pytest.raises(ValueError):
        record_login_attempt(db, "unknown", "value", now)


def test_naive_timestamp_is_rejected(db):
    with pytest.raises(ValueError):
        record_login_attempt(
            db,
            "email",
            "user@example.test",
            datetime(2026, 11, 21, 12, 0),
        )


def test_rate_limit_keys_are_not_stored_as_plaintext(db, now):
    email = "private@example.test"

    record_login_attempt(db, "email", email, now)

    row = db.execute(
        select(LoginRateLimit).where(LoginRateLimit.scope == "email")
    ).scalar_one()

    assert row.key_hash != email
    assert len(row.key_hash) == 64
def test_cleanup_removes_only_expired_counters(db, now):
    record_login_attempt(
        db, "email", "expired@example.test",
        now - WINDOW - timedelta(seconds=1),
    )
    record_login_attempt(
        db, "email", "fresh@example.test", now,
    )

    deleted = cleanup_expired_rate_limits(db, now=now)
    db.commit()

    assert deleted == 1

    rows = db.execute(
        select(LoginRateLimit)
    ).scalars().all()

    assert len(rows) == 1
    assert rows[0].window_started_at == now.replace(tzinfo=None)


def test_cleanup_respects_batch_limit(db, now):
    for index in range(5):
        record_login_attempt(
            db,
            "email",
            f"expired-{index}@example.test",
            now - WINDOW - timedelta(seconds=1),
        )

    deleted = cleanup_expired_rate_limits(
        db,
        now=now,
        batch_size=2,
    )
    db.commit()

    assert deleted == 2

    remaining = db.execute(
        select(LoginRateLimit)
    ).scalars().all()

    assert len(remaining) == 3


def test_cleanup_rejects_invalid_arguments(db, now):
    with pytest.raises(ValueError):
        cleanup_expired_rate_limits(
            db, now=now, batch_size=0,
        )

    with pytest.raises(ValueError):
        cleanup_expired_rate_limits(
            db, now=datetime(2026, 11, 21, 12, 0),
        )