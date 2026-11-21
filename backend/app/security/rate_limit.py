"""Database-backed rate limiting for authentication attempts."""

import hashlib
import hmac
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from app.config import settings
from app.models import LoginRateLimit


WINDOW = timedelta(minutes=15)

LIMITS = {
    "email": 5,
    "ip": 30,
}


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    attempts: int
    limit: int
    retry_after: int


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _key_hash(scope: str, value: str) -> str:
    if scope not in LIMITS:
        raise ValueError("Unsupported rate-limit scope.")

    if not isinstance(value, str) or not value:
        raise ValueError("Rate-limit key must not be empty.")

    message = (
        f"invest:login-rate-limit:v1:{scope}:{value}"
    ).encode("utf-8")

    return hmac.new(
        settings.app_secret_key.encode("utf-8"),
        message,
        hashlib.sha256,
    ).hexdigest()


def _insert_for_dialect(db: Session):
    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        return pg_insert(LoginRateLimit)

    if dialect == "sqlite":
        return sqlite_insert(LoginRateLimit)

    raise RuntimeError(
        f"Unsupported database dialect for rate limiting: {dialect}"
    )


def record_login_attempt(
    db: Session,
    scope: str,
    value: str,
    now: datetime | None = None,
) -> RateLimitResult:
    """Atomically record an attempt and return the resulting limit state."""
    if scope not in LIMITS:
        raise ValueError("Unsupported rate-limit scope.")

    now = now or _utc_now()
    if now.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware.")
    now = now.astimezone(timezone.utc)

    key_hash = _key_hash(scope, value)
    cutoff = now - WINDOW
    table = LoginRateLimit.__table__

    statement = _insert_for_dialect(db).values(
        scope=scope,
        key_hash=key_hash,
        window_started_at=now,
        attempts=1,
    )

    expired = table.c.window_started_at <= cutoff

    statement = statement.on_conflict_do_update(
        index_elements=[table.c.scope, table.c.key_hash],
        set_={
            "window_started_at": case(
                (expired, now),
                else_=table.c.window_started_at,
            ),
            "attempts": case(
                (expired, 1),
                else_=table.c.attempts + 1,
            ),
        },
    ).returning(
        table.c.attempts,
        table.c.window_started_at,
    )

    attempts, window_started_at = db.execute(statement).one()

    if window_started_at.tzinfo is None:
        window_started_at = window_started_at.replace(
            tzinfo=timezone.utc
        )

    expires_at = window_started_at + WINDOW
    retry_after = max(
        1,
        math.ceil((expires_at - now).total_seconds()),
    )

    limit = LIMITS[scope]

    return RateLimitResult(
        allowed=attempts <= limit,
        attempts=attempts,
        limit=limit,
        retry_after=retry_after,
    )


def clear_email_attempts(
    db: Session,
    email: str,
) -> None:
    """Clear the email counter after successful authentication."""
    key_hash = _key_hash("email", email)

    db.execute(
        delete(LoginRateLimit).where(
            LoginRateLimit.scope == "email",
            LoginRateLimit.key_hash == key_hash,
        )
    )
def cleanup_expired_rate_limits(
    db: Session,
    now: datetime | None = None,
    batch_size: int = 500,
) -> int:
    """Delete a bounded batch of expired rate-limit counters."""
    if batch_size < 1:
        raise ValueError("Batch size must be positive.")

    now = now or _utc_now()
    if now.tzinfo is None:
        raise ValueError("Timestamp must be timezone-aware.")

    cutoff = now.astimezone(timezone.utc) - WINDOW
    table = LoginRateLimit.__table__

    expired_keys = (
        select(table.c.scope, table.c.key_hash)
        .where(table.c.window_started_at <= cutoff)
        .order_by(table.c.window_started_at.asc())
        .limit(batch_size)
    )

    statement = delete(LoginRateLimit).where(
        tuple_(table.c.scope, table.c.key_hash).in_(expired_keys),
        table.c.window_started_at <= cutoff,
    )

    result = db.execute(statement)
    return max(0, result.rowcount or 0)