"""Workspace-scoped API token management and validation."""

from datetime import datetime, timezone
import hashlib
import secrets
from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.db import SessionLocal
from app.models import ApiToken, AuditLog, User
from app.security.tenancy import workspace_role

router = APIRouter(tags=["api-tokens"])

ALLOWED_SCOPES = {
    "workflow:run",
    "run:read",
    "findings:read",
    "reports:read",
    "template:publish",
}


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(min_length=1, max_length=8)
    expires_at: datetime | None = None

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Token name is too short.")
        return value

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(value))
        if not normalized or any(scope not in ALLOWED_SCOPES for scope in normalized):
            raise ValueError("One or more API token scopes are not supported.")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Token expiration must include a timezone.")
        if value <= datetime.now(timezone.utc):
            raise ValueError("Token expiration must be in the future.")
        return value


def token_digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def require_workspace_api_token(db, provided_token: str, workspace_id: UUID, scope: str) -> ApiToken:
    if not isinstance(provided_token, str) or not provided_token or len(provided_token) > 512:
        raise HTTPException(status_code=401, detail="Invalid API token.")
    token = db.scalar(
        select(ApiToken).where(
            ApiToken.token_hash == token_digest(provided_token),
            ApiToken.workspace_id == workspace_id,
            ApiToken.revoked_at.is_(None),
        )
    )
    if token is None:
        raise HTTPException(status_code=401, detail="Invalid API token.")
    if token.expires_at is not None:
        expiry = token.expires_at
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            raise HTTPException(status_code=401, detail="API token has expired.")
    if scope not in (token.scopes or []):
        raise HTTPException(status_code=403, detail="API token does not grant the required scope.")
    user = db.get(User, token.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="API token owner is inactive.")
    token.last_used_at = datetime.now(timezone.utc)
    db.flush()
    return token


def _actor(request: Request) -> User:
    actor = getattr(request.state, "user", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return actor


@router.get("/api/workspaces/{workspace_id}/tokens")
def list_api_tokens(workspace_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        if workspace_role(db, actor.id, workspace_id) != "admin":
            raise HTTPException(status_code=404, detail="Workspace not found.")
        rows = db.scalars(
            select(ApiToken)
            .where(ApiToken.workspace_id == workspace_id)
            .order_by(ApiToken.created_at.desc())
        ).all()
        return {"items": [{
            "id": str(row.id),
            "name": row.name,
            "scopes": row.scopes,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
            "revoked_at": row.revoked_at,
            "last_used_at": row.last_used_at,
            "created_by_me": row.user_id == actor.id,
        } for row in rows]}


@router.post("/api/workspaces/{workspace_id}/tokens", status_code=201)
def create_api_token(workspace_id: UUID, payload: ApiTokenCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        if workspace_role(db, actor.id, workspace_id) != "admin":
            raise HTTPException(status_code=404, detail="Workspace not found.")
        raw_token = "inv_" + secrets.token_urlsafe(36)
        row = ApiToken(
            user_id=actor.id,
            workspace_id=workspace_id,
            name=payload.name,
            token_hash=token_digest(raw_token),
            scopes=payload.scopes,
            expires_at=payload.expires_at,
        )
        db.add(row)
        db.flush()
        db.add(AuditLog(
            action="api_token.created",
            entity="api_token",
            entity_id=str(row.id),
            details={"actor_user_id": str(actor.id), "workspace_id": str(workspace_id), "scopes": payload.scopes},
        ))
        db.commit()
        return {
            "id": str(row.id),
            "name": row.name,
            "token": raw_token,
            "scopes": row.scopes,
            "expires_at": row.expires_at,
            "warning": "The token is shown only once. Store it securely.",
        }


@router.delete("/api/workspaces/{workspace_id}/tokens/{token_id}")
def revoke_api_token(workspace_id: UUID, token_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        if workspace_role(db, actor.id, workspace_id) != "admin":
            raise HTTPException(status_code=404, detail="Workspace not found.")
        row = db.scalar(
            select(ApiToken).where(
                ApiToken.id == token_id,
                ApiToken.workspace_id == workspace_id,
            )
        )
        if row is None:
            raise HTTPException(status_code=404, detail="API token not found.")
        if row.revoked_at is None:
            row.revoked_at = datetime.now(timezone.utc)
            db.add(AuditLog(
                action="api_token.revoked",
                entity="api_token",
                entity_id=str(row.id),
                details={"actor_user_id": str(actor.id), "workspace_id": str(workspace_id)},
            ))
            db.commit()
        return {"id": str(row.id), "revoked": True}
