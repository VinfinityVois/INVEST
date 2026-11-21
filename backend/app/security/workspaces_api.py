"""Organization and workspace management API."""

from uuid import UUID

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.db import SessionLocal
from app.models import (
    AuditLog,
    Organization,
    OrganizationMembership,
    User,
    Workspace,
    WorkspaceMembership,
)
from app.security.auth import normalize_email
from app.security.tenancy import accessible_workspaces, require_active_workspace, workspace_role

router = APIRouter(tags=["workspaces"])


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Organization name is too short.")
        return value


class WorkspaceCreate(BaseModel):
    organization_id: UUID
    name: str = Field(min_length=2, max_length=200)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Workspace name is too short.")
        return value


class WorkspaceUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=200)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Workspace name is too short.")
        return value


class WorkspaceMemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    role: str = "viewer"

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        if value not in {"admin", "editor", "analyst", "viewer"}:
            raise ValueError("Unsupported workspace role.")
        return value


class WorkspaceMemberUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        if value not in {"admin", "editor", "analyst", "viewer"}:
            raise ValueError("Unsupported workspace role.")
        return value


class MemberCreate(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    workspace_id: UUID | None = None
    workspace_role: str = "viewer"

    @field_validator("email")
    @classmethod
    def clean_email(cls, value: str) -> str:
        normalized = normalize_email(value)
        if "@" not in normalized or normalized.startswith("@") or normalized.endswith("@"):
            raise ValueError("Enter a valid email address.")
        return normalized

    @field_validator("workspace_role")
    @classmethod
    def valid_workspace_role(cls, value: str) -> str:
        if value not in {"admin", "editor", "analyst", "viewer"}:
            raise ValueError("Unsupported workspace role.")
        return value


def _actor(request: Request) -> User:
    actor = getattr(request.state, "user", None)
    if actor is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return actor


def _organization_role(db, organization_id: UUID, user_id: UUID):
    return db.scalar(
        select(OrganizationMembership.role).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == user_id,
        )
    )


def _audit(db, actor: User, action: str, entity: str, entity_id, details=None):
    db.add(AuditLog(
        action=action,
        entity=entity,
        entity_id=str(entity_id),
        details={"actor_user_id": str(actor.id), **(details or {})},
    ))


@router.get("/api/organizations")
def list_organizations(request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        memberships = db.scalars(
            select(OrganizationMembership).where(OrganizationMembership.user_id == actor.id)
        ).all()
        result = []
        for membership in memberships:
            organization = db.get(Organization, membership.organization_id)
            if organization is None:
                continue
            result.append({
                "id": str(organization.id),
                "name": organization.name,
                "kind": organization.kind,
                "role": membership.role,
            })
        return {"items": result}


@router.post("/api/organizations", status_code=201)
def create_organization(payload: OrganizationCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        organization = Organization(name=payload.name, kind="organization")
        db.add(organization)
        db.flush()
        workspace = Workspace(
            organization_id=organization.id,
            name="General",
            is_default=True,
        )
        db.add(workspace)
        db.flush()
        db.add(OrganizationMembership(
            organization_id=organization.id,
            user_id=actor.id,
            role="owner",
        ))
        db.add(WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=actor.id,
            role="admin",
        ))
        _audit(db, actor, "organization.created", "organization", organization.id)
        db.commit()
        return {
            "id": str(organization.id),
            "name": organization.name,
            "kind": organization.kind,
            "default_workspace_id": str(workspace.id),
        }


@router.get("/api/workspaces")
def list_workspaces(request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        active_id = getattr(request.state, "current_workspace_id", None)
        items = []
        for workspace in accessible_workspaces(db, actor.id):
            organization = db.get(Organization, workspace.organization_id)
            items.append({
                "id": str(workspace.id),
                "name": workspace.name,
                "organization_id": str(workspace.organization_id),
                "organization_name": organization.name if organization else "",
                "role": workspace_role(db, actor.id, workspace.id),
                "is_default": workspace.is_default,
                "active": str(workspace.id) == str(active_id),
            })
        return {"items": items}


@router.get("/api/workspaces/active")
def get_active_workspace(request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        workspace, role = require_active_workspace(db, request)
        organization = db.get(Organization, workspace.organization_id)
        db.commit()
        return {
            "id": str(workspace.id),
            "name": workspace.name,
            "organization_id": str(workspace.organization_id),
            "organization_name": organization.name if organization else "",
            "role": role,
        }


@router.post("/api/workspaces", status_code=201)
def create_workspace(payload: WorkspaceCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = _organization_role(db, payload.organization_id, actor.id)
        if role not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Organization administrator permission required.")
        organization = db.get(Organization, payload.organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        workspace = Workspace(
            organization_id=organization.id,
            name=payload.name,
            is_default=False,
        )
        db.add(workspace)
        db.flush()
        db.add(WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=actor.id,
            role="admin",
        ))
        _audit(db, actor, "workspace.created", "workspace", workspace.id, {
            "organization_id": str(organization.id),
        })
        db.commit()
        return {
            "id": str(workspace.id),
            "name": workspace.name,
            "organization_id": str(organization.id),
            "role": "admin",
        }


@router.patch("/api/workspaces/{workspace_id}")
def update_workspace(workspace_id: UUID, payload: WorkspaceUpdate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = workspace_role(db, actor.id, workspace_id)
        if role != "admin":
            raise HTTPException(status_code=403, detail="Workspace administrator permission required.")
        workspace = db.get(Workspace, workspace_id)
        if workspace is None or workspace.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        workspace.name = payload.name
        _audit(db, actor, "workspace.updated", "workspace", workspace.id)
        db.commit()
        return {"id": str(workspace.id), "name": workspace.name}


@router.post("/api/workspaces/{workspace_id}/switch")
def switch_workspace(workspace_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = workspace_role(db, actor.id, workspace_id)
        if role is None:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        workspace = db.get(Workspace, workspace_id)
        if workspace is None or workspace.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        session_id = getattr(request.state, "user_session_id", None)
        from app.models import UserSession
        session = db.get(UserSession, session_id) if session_id else None
        if session is None or session.user_id != actor.id or session.revoked_at is not None:
            raise HTTPException(status_code=401, detail="Authentication required")
        previous = session.current_workspace_id
        session.current_workspace_id = workspace.id
        _audit(db, actor, "workspace.switched", "workspace", workspace.id, {
            "previous_workspace_id": str(previous) if previous else None,
        })
        db.commit()
        organization = db.get(Organization, workspace.organization_id)
        return {
            "id": str(workspace.id),
            "name": workspace.name,
            "organization_id": str(workspace.organization_id),
            "organization_name": organization.name if organization else "",
            "role": role,
        }


@router.get("/api/organizations/{organization_id}/members")
def list_organization_members(organization_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == actor.id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        rows = db.scalars(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id
            )
        ).all()
        items = []
        for row in rows:
            user = db.get(User, row.user_id)
            if user is not None:
                items.append({
                    "user_id": str(user.id),
                    "email": user.email,
                    "role": row.role,
                    "is_active": user.is_active,
                })
        return {"items": items}




@router.get("/api/workspaces/{workspace_id}/members")
def list_workspace_members(workspace_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = workspace_role(db, actor.id, workspace_id)
        if role is None:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        rows = db.scalars(
            select(WorkspaceMembership).where(WorkspaceMembership.workspace_id == workspace_id)
        ).all()
        items = []
        for row in rows:
            user = db.get(User, row.user_id)
            if user is not None:
                items.append({
                    "user_id": str(user.id),
                    "email": user.email,
                    "role": row.role,
                    "is_active": user.is_active,
                })
        return {"items": items}


@router.post("/api/workspaces/{workspace_id}/members", status_code=201)
def add_workspace_member(workspace_id: UUID, payload: WorkspaceMemberCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = workspace_role(db, actor.id, workspace_id)
        if role != "admin":
            raise HTTPException(status_code=403, detail="Workspace administrator permission required.")
        workspace = db.get(Workspace, workspace_id)
        if workspace is None or workspace.deleted_at is not None:
            raise HTTPException(status_code=404, detail="Workspace not found.")
        user = db.scalar(select(User).where(User.email == payload.email, User.is_active.is_(True)))
        if user is None:
            raise HTTPException(status_code=404, detail="Active user not found.")
        organization_member = db.scalar(
            select(OrganizationMembership.id).where(
                OrganizationMembership.organization_id == workspace.organization_id,
                OrganizationMembership.user_id == user.id,
            )
        )
        if organization_member is None:
            raise HTTPException(status_code=409, detail="Add the user to the organization before assigning a workspace.")
        existing = db.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.workspace_id == workspace_id,
                WorkspaceMembership.user_id == user.id,
            )
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="User is already a workspace member.")
        db.add(WorkspaceMembership(
            workspace_id=workspace_id,
            user_id=user.id,
            role=payload.role,
        ))
        _audit(db, actor, "workspace.member_added", "workspace", workspace_id, {
            "member_user_id": str(user.id),
            "role": payload.role,
        })
        db.commit()
        return {"user_id": str(user.id), "email": user.email, "role": payload.role}


@router.patch("/api/workspaces/{workspace_id}/members/{user_id}")
def update_workspace_member(workspace_id: UUID, user_id: UUID, payload: WorkspaceMemberUpdate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        if workspace_role(db, actor.id, workspace_id) != "admin":
            raise HTTPException(status_code=403, detail="Workspace administrator permission required.")
        membership = db.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.workspace_id == workspace_id,
                WorkspaceMembership.user_id == user_id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="Workspace member not found.")
        previous_role = membership.role
        membership.role = payload.role
        _audit(db, actor, "workspace.member_role_updated", "workspace", workspace_id, {
            "member_user_id": str(user_id),
            "previous_role": previous_role,
            "role": payload.role,
        })
        db.commit()
        return {"user_id": str(user_id), "role": membership.role}


@router.delete("/api/workspaces/{workspace_id}/members/{user_id}")
def remove_workspace_member(workspace_id: UUID, user_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        if workspace_role(db, actor.id, workspace_id) != "admin":
            raise HTTPException(status_code=403, detail="Workspace administrator permission required.")
        membership = db.scalar(
            select(WorkspaceMembership).where(
                WorkspaceMembership.workspace_id == workspace_id,
                WorkspaceMembership.user_id == user_id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="Workspace member not found.")
        db.delete(membership)
        _audit(db, actor, "workspace.member_removed", "workspace", workspace_id, {
            "member_user_id": str(user_id),
        })
        db.commit()
        return {"status": "removed"}


@router.delete("/api/organizations/{organization_id}/members/{user_id}")
def remove_organization_member(organization_id: UUID, user_id: UUID, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = _organization_role(db, organization_id, actor.id)
        if role not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Organization administrator permission required.")
        membership = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user_id,
            )
        )
        if membership is None:
            raise HTTPException(status_code=404, detail="Organization member not found.")
        if membership.role == "owner":
            raise HTTPException(status_code=409, detail="Transfer organization ownership before removing its owner.")
        workspace_ids = select(Workspace.id).where(Workspace.organization_id == organization_id)
        db.query(WorkspaceMembership).filter(
            WorkspaceMembership.user_id == user_id,
            WorkspaceMembership.workspace_id.in_(workspace_ids),
        ).delete(synchronize_session=False)
        db.delete(membership)
        _audit(db, actor, "organization.member_removed", "organization", organization_id, {
            "member_user_id": str(user_id),
        })
        db.commit()
        return {"status": "removed"}


class OwnershipTransfer(BaseModel):
    new_owner_user_id: UUID
    confirm: bool


@router.post("/api/organizations/{organization_id}/transfer-ownership")
def transfer_organization_ownership(organization_id: UUID, payload: OwnershipTransfer, request: Request):
    actor = _actor(request)
    if not payload.confirm:
        raise HTTPException(status_code=422, detail="Explicit ownership transfer confirmation is required.")
    with SessionLocal() as db:
        current = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == actor.id,
            ).with_for_update()
        )
        if current is None or current.role != "owner":
            raise HTTPException(status_code=403, detail="Only the current organization owner can transfer ownership.")
        target = db.scalar(
            select(OrganizationMembership)
            .join(User, User.id == OrganizationMembership.user_id)
            .where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == payload.new_owner_user_id,
                User.is_active.is_(True),
            )
            .with_for_update()
        )
        if target is None:
            raise HTTPException(status_code=404, detail="New owner must already be an organization member.")
        if target.user_id == actor.id:
            raise HTTPException(status_code=422, detail="Choose another organization member.")
        current.role = "member"
        db.flush()
        target.role = "owner"
        _audit(db, actor, "organization.ownership_transferred", "organization", organization_id, {
            "previous_owner_user_id": str(actor.id),
            "new_owner_user_id": str(target.user_id),
        })
        db.commit()
        return {"organization_id": str(organization_id), "owner_user_id": str(target.user_id)}


@router.post("/api/organizations/{organization_id}/members", status_code=201)
def add_organization_member(organization_id: UUID, payload: MemberCreate, request: Request):
    actor = _actor(request)
    with SessionLocal() as db:
        role = _organization_role(db, organization_id, actor.id)
        if role not in {"owner", "admin"}:
            raise HTTPException(status_code=403, detail="Organization administrator permission required.")
        user = db.scalar(select(User).where(User.email == payload.email))
        if user is None or not user.is_active:
            raise HTTPException(status_code=404, detail="Active user not found.")
        organization = db.get(Organization, organization_id)
        if organization is None:
            raise HTTPException(status_code=404, detail="Organization not found.")
        existing = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user.id,
            )
        )
        if existing is not None:
            raise HTTPException(status_code=409, detail="User is already a member.")
        membership = OrganizationMembership(
            organization_id=organization_id,
            user_id=user.id,
            role="member",
        )
        db.add(membership)
        if payload.workspace_id is not None:
            workspace = db.get(Workspace, payload.workspace_id)
            if workspace is None or workspace.organization_id != organization_id or workspace.deleted_at is not None:
                raise HTTPException(status_code=422, detail="Workspace does not belong to this organization.")
            db.add(WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=user.id,
                role=payload.workspace_role,
            ))
        _audit(db, actor, "organization.member_added", "organization", organization_id, {
            "member_user_id": str(user.id),
            "workspace_id": str(payload.workspace_id) if payload.workspace_id else None,
        })
        db.commit()
        return {"user_id": str(user.id), "email": user.email, "role": "member"}
