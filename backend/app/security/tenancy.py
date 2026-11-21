"""Workspace membership provisioning helpers."""

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import (
    Organization,
    OrganizationMembership,
    User,
    Workspace,
    WorkspaceMembership,
    UserSession,
)


def create_personal_workspace(db: Session, user: User) -> Workspace:
    """Provision the user's private organization and default workspace."""
    organization = Organization(
        name=f"{user.email}'s personal organization",
        kind="personal",
    )
    db.add(organization)
    db.flush()

    workspace = Workspace(
        organization_id=organization.id,
        name="Personal workspace",
        is_default=True,
    )
    db.add(workspace)
    db.flush()

    db.add(OrganizationMembership(
        organization_id=organization.id,
        user_id=user.id,
        role="owner",
    ))
    db.add(WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role="admin",
    ))
    db.flush()
    return workspace


def claim_unassigned_legacy_workspace(db: Session, user: User) -> bool:
    """Let the first bootstrap admin claim pre-authentication project data."""
    organization = db.scalar(
        select(Organization)
        .where(
            Organization.name == "Legacy organization",
            Organization.kind == "organization",
            ~select(OrganizationMembership.id)
            .where(OrganizationMembership.organization_id == Organization.id)
            .exists(),
        )
        .with_for_update()
    )
    if organization is None:
        return False

    db.add(OrganizationMembership(
        organization_id=organization.id,
        user_id=user.id,
        role="owner",
    ))
    workspaces = db.scalars(
        select(Workspace).where(Workspace.organization_id == organization.id)
    ).all()
    for workspace in workspaces:
        db.add(WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role="admin",
        ))
    db.flush()
    return True


def workspace_role(db: Session, user_id, workspace_id):
    """Resolve direct workspace membership or inherited organization admin access."""
    direct = db.scalar(
        select(WorkspaceMembership.role).where(
            WorkspaceMembership.user_id == user_id,
            WorkspaceMembership.workspace_id == workspace_id,
        )
    )
    if direct is not None:
        return direct
    organization_id = db.scalar(
        select(Workspace.organization_id).where(
            Workspace.id == workspace_id,
            Workspace.deleted_at.is_(None),
        )
    )
    if organization_id is None:
        return None
    organization_role = db.scalar(
        select(OrganizationMembership.role).where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.organization_id == organization_id,
        )
    )
    return "admin" if organization_role in {"owner", "admin"} else None


def require_active_workspace(db: Session, request, allowed_roles=None) -> tuple[Workspace, str]:
    """Resolve and validate the workspace stored on this server-side session."""
    user = getattr(request.state, "user", None)
    session_id = getattr(request.state, "user_session_id", None)
    if user is None or session_id is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Authentication required")
    session = db.get(UserSession, session_id)
    if session is None or session.user_id != user.id or session.revoked_at is not None:
        from fastapi import HTTPException
        raise HTTPException(status_code=401, detail="Authentication required")

    workspace_id = session.current_workspace_id
    role = workspace_role(db, user.id, workspace_id) if workspace_id else None
    if role is None:
        candidate = db.scalar(
            select(Workspace.id)
            .join(WorkspaceMembership, WorkspaceMembership.workspace_id == Workspace.id)
            .where(
                WorkspaceMembership.user_id == user.id,
                Workspace.deleted_at.is_(None),
            )
            .order_by(Workspace.is_default.desc(), Workspace.created_at.asc(), Workspace.id)
            .limit(1)
        )
        if candidate is None:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="No workspace access is configured for this account.")
        workspace_id = candidate
        session.current_workspace_id = candidate
        db.flush()
        role = workspace_role(db, user.id, candidate)

    workspace = db.get(Workspace, workspace_id)
    if workspace is None or workspace.deleted_at is not None or role is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Workspace not found.")
    if allowed_roles is not None and role not in set(allowed_roles) and role != "admin":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Workspace permission required.")
    return workspace, role


def accessible_workspaces(db: Session, user_id):
    """List workspaces directly assigned or inherited through organization admin."""
    direct_ids = select(WorkspaceMembership.workspace_id).where(
        WorkspaceMembership.user_id == user_id
    )
    admin_org_ids = select(OrganizationMembership.organization_id).where(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.role.in_(("owner", "admin")),
    )
    return db.scalars(
        select(Workspace)
        .where(
            Workspace.deleted_at.is_(None),
            or_(
                Workspace.id.in_(direct_ids),
                Workspace.organization_id.in_(admin_org_ids),
            ),
        )
        .order_by(Workspace.created_at.asc(), Workspace.name)
    ).all()
