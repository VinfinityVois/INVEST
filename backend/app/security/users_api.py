"""Administrative user management and self-service session endpoints."""

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, or_, select

from app.db import SessionLocal
from app.models import AuditLog, User, UserSession
from app.security.auth import normalize_email
from app.security.passwords import hash_password, verify_password

router = APIRouter(tags=["user management"])


class UserCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=12, max_length=1024)
    is_admin: bool = False

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, min_length=3, max_length=320)
    is_admin: bool | None = None
    is_active: bool | None = None

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = normalize_email(value)
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class ProfileUpdate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    current_password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def valid_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized


def _actor(db, request: Request, *, admin: bool = False) -> User:
    session_user = getattr(request.state, "user", None)
    if session_user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    actor = db.get(User, session_user.id)
    if actor is None or not actor.is_active:
        raise HTTPException(status_code=401, detail="Authentication required")
    if admin and not actor.is_admin:
        raise HTTPException(status_code=403, detail="Administrator permission required")
    return actor


def _user_payload(db, user: User) -> dict:
    active_sessions = db.scalar(
        select(func.count(UserSession.id)).where(
            UserSession.user_id == user.id,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(timezone.utc),
        )
    ) or 0
    return {
        "id": str(user.id),
        "email": user.email,
        "is_admin": user.is_admin,
        "role": "admin" if user.is_admin else "user",
        "is_active": user.is_active,
        "active_sessions": active_sessions,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "updated_at": user.updated_at.isoformat() if user.updated_at else None,
    }


def _audit(db, actor: User, action: str, target: User, details: dict | None = None) -> None:
    db.add(AuditLog(
        action=action,
        entity="user",
        entity_id=str(target.id),
        details={"actor_user_id": str(actor.id), **(details or {})},
    ))


@router.get("/api/admin/users")
def list_users(
    request: Request,
    q: str = Query(default="", max_length=200),
    status: str = Query(default="all", pattern="^(all|active|inactive)$"),
    role: str = Query(default="all", pattern="^(all|admin|user)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
):
    with SessionLocal() as db:
        _actor(db, request, admin=True)
        filters = []
        if q.strip():
            needle = f"%{q.strip().lower()}%"
            filters.append(func.lower(User.email).like(needle))
        if status == "active":
            filters.append(User.is_active.is_(True))
        elif status == "inactive":
            filters.append(User.is_active.is_(False))
        if role == "admin":
            filters.append(User.is_admin.is_(True))
        elif role == "user":
            filters.append(User.is_admin.is_(False))

        total = db.scalar(select(func.count(User.id)).where(*filters)) or 0
        users = db.scalars(
            select(User).where(*filters)
            .order_by(User.created_at.desc(), User.id)
            .offset((page - 1) * page_size)
            .limit(page_size)
        ).all()
        return {
            "items": [_user_payload(db, user) for user in users],
            "page": page,
            "page_size": page_size,
            "total": total,
            "pages": (total + page_size - 1) // page_size,
        }


@router.post("/api/admin/users", status_code=201)
def create_user(payload: UserCreate, request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request, admin=True)
        if db.scalar(select(User.id).where(User.email == payload.email)):
            raise HTTPException(status_code=409, detail="A user with this email already exists.")
        user = User(
            email=payload.email,
            password_hash=hash_password(payload.password),
            is_active=True,
            is_admin=payload.is_admin,
        )
        db.add(user)
        db.flush()
        _audit(db, actor, "user.created", user, {"is_admin": user.is_admin})
        db.commit()
        db.refresh(user)
        return _user_payload(db, user)


@router.patch("/api/admin/users/{user_id}")
def update_user(user_id: UUID, payload: UserUpdate, request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request, admin=True)
        user = db.get(User, user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="User not found.")

        changes = payload.model_dump(exclude_unset=True)
        if not changes:
            raise HTTPException(status_code=422, detail="No changes supplied.")
        if "email" in changes and changes["email"] is None:
            raise HTTPException(status_code=422, detail="Email cannot be null.")
        if "email" in changes and db.scalar(
            select(User.id).where(User.email == changes["email"], User.id != user.id)
        ):
            raise HTTPException(status_code=409, detail="A user with this email already exists.")

        next_admin = changes.get("is_admin", user.is_admin)
        next_active = changes.get("is_active", user.is_active)
        if user.id == actor.id and (not next_active or not next_admin):
            raise HTTPException(status_code=409, detail="You cannot deactivate or demote your own administrator account.")

        if user.is_admin and user.is_active and (not next_admin or not next_active):
            # Lock the active administrator set to prevent concurrent removal
            # of the final administrator on PostgreSQL.
            active_admins = db.scalars(
                select(User).where(User.is_admin.is_(True), User.is_active.is_(True)).with_for_update()
            ).all()
            if len(active_admins) <= 1:
                raise HTTPException(status_code=409, detail="At least one active administrator must remain.")

        before = {"email": user.email, "is_admin": user.is_admin, "is_active": user.is_active}
        for key, value in changes.items():
            setattr(user, key, value)

        if not user.is_active:
            now = datetime.now(timezone.utc)
            db.query(UserSession).filter(
                UserSession.user_id == user.id,
                UserSession.revoked_at.is_(None),
            ).update({UserSession.revoked_at: now}, synchronize_session=False)

        _audit(db, actor, "user.updated", user, {"before": before, "after": {
            "email": user.email, "is_admin": user.is_admin, "is_active": user.is_active
        }})
        db.commit()
        db.refresh(user)
        return _user_payload(db, user)


@router.get("/api/auth/sessions")
def list_my_sessions(request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request)
        raw_token = request.cookies.get("invest_session", "")
        import hashlib
        current_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest() if raw_token else None
        sessions = db.scalars(
            select(UserSession).where(UserSession.user_id == actor.id)
            .order_by(UserSession.created_at.desc())
        ).all()
        now = datetime.now(timezone.utc)
        def expired(value: datetime) -> bool:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value <= now
        return {"items": [{
            "id": str(item.id),
            "created_at": item.created_at.isoformat() if item.created_at else None,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None,
            "expires_at": item.expires_at.isoformat(),
            "revoked": item.revoked_at is not None or expired(item.expires_at),
            "current": item.token_hash == current_hash,
        } for item in sessions]}


@router.delete("/api/auth/sessions/{session_id}")
def revoke_my_session(session_id: UUID, request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request)
        session = db.scalar(select(UserSession).where(
            UserSession.id == session_id,
            UserSession.user_id == actor.id,
        ))
        if session is None:
            raise HTTPException(status_code=404, detail="Session not found.")
        if session.revoked_at is None:
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()
        return {"status": "revoked"}


@router.delete("/api/auth/sessions")
def revoke_other_sessions(request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request)
        raw_token = request.cookies.get("invest_session", "")
        import hashlib
        current_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest() if raw_token else None
        query = db.query(UserSession).filter(
            UserSession.user_id == actor.id,
            UserSession.revoked_at.is_(None),
        )
        if current_hash:
            query = query.filter(UserSession.token_hash != current_hash)
        count = query.update(
            {UserSession.revoked_at: datetime.now(timezone.utc)},
            synchronize_session=False,
        )
        db.commit()
        return {"status": "revoked", "count": count}


@router.patch("/api/auth/profile")
def update_my_profile(payload: ProfileUpdate, request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request)
        if not verify_password(payload.current_password, actor.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        duplicate = db.scalar(select(User.id).where(User.email == payload.email, User.id != actor.id))
        if duplicate:
            raise HTTPException(status_code=409, detail="A user with this email already exists.")
        previous_email = actor.email
        actor.email = payload.email
        db.add(AuditLog(
            action="user.profile_updated",
            entity="user",
            entity_id=str(actor.id),
            details={"actor_user_id": str(actor.id), "previous_email": previous_email, "email_changed": previous_email != actor.email},
        ))
        db.commit()
        return {"id": str(actor.id), "email": actor.email, "is_admin": actor.is_admin}


@router.post("/api/auth/password")
def change_my_password(payload: PasswordChange, request: Request):
    with SessionLocal() as db:
        actor = _actor(db, request)
        if not verify_password(payload.current_password, actor.password_hash):
            raise HTTPException(status_code=400, detail="Current password is incorrect.")
        actor.password_hash = hash_password(payload.new_password)
        raw_token = request.cookies.get("invest_session", "")
        import hashlib
        current_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest() if raw_token else None
        query = db.query(UserSession).filter(
            UserSession.user_id == actor.id,
            UserSession.revoked_at.is_(None),
        )
        if current_hash:
            query = query.filter(UserSession.token_hash != current_hash)
        query.update(
            {UserSession.revoked_at: datetime.now(timezone.utc)},
            synchronize_session=False,
        )
        db.add(AuditLog(
            action="user.password_changed",
            entity="user",
            entity_id=str(actor.id),
            details={"actor_user_id": str(actor.id)},
        ))
        db.commit()
        return {"status": "password_changed", "other_sessions_revoked": True}
