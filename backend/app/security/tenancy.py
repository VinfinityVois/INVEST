"""Workspace membership provisioning helpers."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Organization,
    OrganizationMembership,
    User,
    Workspace,
    WorkspaceMembership,
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
    return True
