"""Authentication helpers for user credentials."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.security.passwords import verify_password


# Precomputed Argon2id hash used when an account does not exist.
# Keep its parameters aligned with app.security.passwords.
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$koSdB/7W51jWTPfAf/I+/Q"
    "$IQ8RV/yz4l/IhcKC2WbMjxHsJvYzQn5jZihiDGtTzxk"
)


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
        normalized_email = None

    if not isinstance(password, str) or not password:
        return None

    user = None
    if normalized_email is not None:
        user = db.execute(
            select(User).where(User.email == normalized_email)
        ).scalar_one_or_none()

    if user is None:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return None

    if not verify_password(password, user.password_hash):
        return None

    if not user.is_active:
        return None

    return user
