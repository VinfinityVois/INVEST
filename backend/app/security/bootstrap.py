"""Safe one-time bootstrap for the first system administrator."""

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.models import User
from app.security.tenancy import claim_unassigned_legacy_workspace, create_personal_workspace
from app.security.auth import normalize_email
from app.security.passwords import hash_password


def _acquire_bootstrap_lock(db: Session) -> None:
    dialect = db.get_bind().dialect.name

    if dialect == "postgresql":
        db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": 731904261},
        )
        return

    if dialect == "sqlite":
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        return

    raise RuntimeError(
        f"Bootstrap locking is not implemented for database: {dialect}"
    )


def create_bootstrap_admin(db: Session, email: str, password: str) -> User:
    """Create the first administrator without modifying existing accounts."""
    normalized_email = normalize_email(email)

    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        raise ValueError("Password must contain between 12 and 1024 characters.")

    _acquire_bootstrap_lock(db)

    existing_admin = db.execute(
        select(User.id).where(User.is_admin.is_(True)).limit(1)
    ).scalar_one_or_none()

    if existing_admin is not None:
        raise ValueError("An administrator already exists. Bootstrap is disabled.")

    existing_user = db.execute(
        select(User.id).where(User.email == normalized_email).limit(1)
    ).scalar_one_or_none()

    if existing_user is not None:
        raise ValueError("A user with this email already exists.")

    user = User(
        email=normalized_email,
        password_hash=hash_password(password),
        is_active=True,
        is_admin=True,
    )
    db.add(user)
    db.flush()
    create_personal_workspace(db, user)
    claim_unassigned_legacy_workspace(db, user)

    return user
