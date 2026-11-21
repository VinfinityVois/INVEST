"""Authentication helpers for user credentials."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.security.passwords import verify_password


def normalize_email(email: str) -> str:
    """Normalize an email address for consistent lookup and storage."""
    if not isinstance(email, str):
        raise ValueError("Email must be a string.")

    normalized = email.strip().lower()

    if not normalized or len(normalized) > 320:
        raise ValueError("Email is empty or too long.")

    return normalized


def authenticate_user(
    db: Session,
    email: str,
    password: str,
) -> User | None:
    """Return an active user when the supplied credentials are valid."""
    try:
        normalized_email = normalize_email(email)
    except ValueError:
        return None

    if not isinstance(password, str) or not password:
        return None

    user = db.execute(
        select(User).where(User.email == normalized_email)
    ).scalar_one_or_none()

    if user is None:
        return None

    if not verify_password(password, user.password_hash):
        return None

    if not user.is_active:
        return None

    return user
