"""Server-side session lifecycle helpers."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User, UserSession, Workspace, WorkspaceMembership


DEFAULT_SESSION_LIFETIME = timedelta(hours=12)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(
    db: Session,
    user_id: UUID,
    lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
) -> tuple[str, UserSession]:
    """Create a session and return its raw token exactly once."""
    if lifetime <= timedelta(0):
        raise ValueError("Session lifetime must be positive.")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise ValueError("Cannot create a session for an inactive or missing user.")

    token = secrets.token_urlsafe(32)
    now = _utc_now()

    default_workspace_id = db.scalar(
        select(Workspace.id)
        .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
        .where(
            WorkspaceMembership.user_id == user_id,
            Workspace.deleted_at.is_(None),
        )
        .order_by(Workspace.is_default.desc(), Workspace.created_at.asc(), Workspace.id)
        .limit(1)
    )
    session = UserSession(
        user_id=user_id,
        current_workspace_id=default_workspace_id,
        token_hash=_hash_token(token),
        expires_at=now + lifetime,
        last_seen_at=now,
    )
    db.add(session)
    db.flush()

    return token, session


def get_session_context(
    db: Session,
    token: str | None,
) -> tuple[User, UserSession] | None:
    """Return the active user and session for a valid opaque token."""
    if not isinstance(token, str) or not token:
        return None

    now = _utc_now()
    result = db.execute(
        select(UserSession, User)
        .join(User, User.id == UserSession.user_id)
        .where(
            UserSession.token_hash == _hash_token(token),
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > now,
            User.is_active.is_(True),
        )
    ).one_or_none()

    if result is None:
        return None

    session, user = result
    session.last_seen_at = now
    db.flush()
    return user, session


def get_user_for_session(
    db: Session,
    token: str | None,
) -> User | None:
    """Compatibility helper returning only the authenticated user."""
    context = get_session_context(db, token)
    return context[0] if context is not None else None


def revoke_session(
    db: Session,
    token: str | None,
) -> bool:
    """Revoke a session by its raw token. Return whether one was found."""
    if not isinstance(token, str) or not token:
        return False

    session = db.execute(
        select(UserSession).where(
            UserSession.token_hash == _hash_token(token),
            UserSession.revoked_at.is_(None),
        )
    ).scalar_one_or_none()

    if session is None:
        return False

    session.revoked_at = _utc_now()
    db.flush()
    return True
