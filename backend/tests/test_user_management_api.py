import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import Organization, OrganizationMembership, Project, User, UserSession, Workflow, WorkflowRun, Workspace, WorkspaceMembership
from app.security.passwords import hash_password, verify_password
from app.security.sessions import create_session
import app.main as main
import app.security.api as auth_api
import app.security.users_api as users_api
import app.security.workspaces_api as workspaces_api
import app.security.tokens_api as tokens_api
from app.security.tenancy import create_personal_workspace


@pytest.fixture
def user_client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with TestingSession() as db:
        admin = User(
            id=uuid.uuid4(),
            email="admin@example.test",
            password_hash=hash_password("CorrectPassword123!"),
            is_active=True,
            is_admin=True,
        )
        member = User(
            id=uuid.uuid4(),
            email="member@example.test",
            password_hash=hash_password("MemberPassword123!"),
            is_active=True,
            is_admin=False,
        )
        db.add_all([admin, member])
        db.flush()
        create_personal_workspace(db, admin)
        create_personal_workspace(db, member)
        db.commit()
        member_id = member.id

    monkeypatch.setattr(main, "SessionLocal", TestingSession)
    monkeypatch.setattr(auth_api, "SessionLocal", TestingSession)
    monkeypatch.setattr(users_api, "SessionLocal", TestingSession)
    monkeypatch.setattr(workspaces_api, "SessionLocal", TestingSession)
    monkeypatch.setattr(tokens_api, "SessionLocal", TestingSession)

    with TestClient(main.app) as client:
        yield client, TestingSession, member_id

    engine.dispose()


def login(client, email="admin@example.test", password="CorrectPassword123!"):
    return client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
        headers={"Origin": "http://localhost:5173"},
    )


def test_admin_can_create_search_and_paginate_users(user_client):
    client, TestingSession, _ = user_client
    assert login(client).status_code == 200

    created = client.post(
        "/api/admin/users",
        json={
            "email": "  analyst@example.test ",
            "password": "AnalystPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert created.status_code == 201
    payload = created.json()
    assert payload["email"] == "analyst@example.test"
    assert payload["role"] == "user"
    assert payload["is_active"] is True
    assert "password" not in payload
    assert "password_hash" not in payload

    listing = client.get("/api/admin/users?q=analyst&page=1&page_size=1")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    assert listing.json()["items"][0]["id"] == payload["id"]
    assert listing.json()["pages"] == 1

    with TestingSession() as db:
        user = db.scalar(select(User).where(User.email == "analyst@example.test"))
        assert user is not None
        assert verify_password("AnalystPassword123!", user.password_hash)
        organization_membership = db.scalar(
            select(OrganizationMembership).where(OrganizationMembership.user_id == user.id)
        )
        workspace_membership = db.scalar(
            select(WorkspaceMembership).where(WorkspaceMembership.user_id == user.id)
        )
        assert organization_membership is not None
        assert organization_membership.role == "owner"
        assert workspace_membership is not None
        assert workspace_membership.role == "admin"


def test_user_management_requires_admin_permission(user_client):
    client, _, _ = user_client
    assert login(client, "member@example.test", "MemberPassword123!").status_code == 200

    response = client.get("/api/admin/users")
    assert response.status_code == 403


def test_user_management_requires_authentication(user_client):
    client, _, _ = user_client
    response = client.get("/api/admin/users")
    assert response.status_code == 401


def test_admin_can_update_user_and_deactivation_revokes_sessions(user_client):
    client, TestingSession, member_id = user_client
    assert login(client).status_code == 200

    with TestingSession.begin() as db:
        token, _ = create_session(db, member_id)

    response = client.patch(
        f"/api/admin/users/{member_id}",
        json={"is_active": False},
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert response.json()["active_sessions"] == 0

    with TestingSession() as db:
        session = db.scalar(select(UserSession).where(UserSession.token_hash.is_not(None), UserSession.user_id == member_id))
        assert session is not None
        assert session.revoked_at is not None


def test_cannot_remove_last_active_administrator(user_client):
    client, _, _ = user_client
    assert login(client).status_code == 200
    response = client.patch(
        f"/api/admin/users/{client.get('/api/auth/me').json()['id']}",
        json={"is_admin": False},
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 409


def test_session_list_revoke_and_password_change(user_client):
    client, TestingSession, _ = user_client
    assert login(client).status_code == 200

    with TestingSession.begin() as db:
        actor = db.scalar(select(User).where(User.email == "admin@example.test"))
        create_session(db, actor.id)

    sessions = client.get("/api/auth/sessions")
    assert sessions.status_code == 200
    assert len(sessions.json()["items"]) == 2
    current = next(item for item in sessions.json()["items"] if item["current"])
    other = next(item for item in sessions.json()["items"] if not item["current"])

    revoked = client.delete(f"/api/auth/sessions/{other['id']}", headers={"Origin": "http://localhost:5173"})
    assert revoked.status_code == 200

    all_revoked = client.delete("/api/auth/sessions", headers={"Origin": "http://localhost:5173"})
    assert all_revoked.status_code == 200
    assert all_revoked.json()["count"] == 0

    changed = client.post(
        "/api/auth/password",
        json={
            "current_password": "CorrectPassword123!",
            "new_password": "NewCorrectPassword456!",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert changed.status_code == 200
    assert changed.json()["other_sessions_revoked"] is True
    assert client.get("/api/auth/me").status_code == 200


def test_profile_email_change_requires_current_password_and_is_audited(user_client):
    client, TestingSession, _ = user_client
    assert login(client).status_code == 200

    rejected = client.patch(
        "/api/auth/profile",
        json={"email": "new-admin@example.test", "current_password": "WrongPassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert rejected.status_code == 400

    changed = client.patch(
        "/api/auth/profile",
        json={"email": " New-Admin@example.test ", "current_password": "CorrectPassword123!"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert changed.status_code == 200
    assert changed.json()["email"] == "new-admin@example.test"

    with TestingSession() as db:
        admin = db.scalar(select(User).where(User.email == "new-admin@example.test"))
        assert admin is not None
        from app.models import AuditLog
        event = db.scalar(select(AuditLog).where(AuditLog.action == "user.profile_updated"))
        assert event is not None
        assert event.details["actor_user_id"] == str(admin.id)


@pytest.mark.parametrize("field", ["email", "is_admin", "is_active"])
def test_admin_update_rejects_null_fields(user_client, field):
    client, _, member_id = user_client
    assert login(client).status_code == 200
    response = client.patch(
        f"/api/admin/users/{member_id}",
        json={field: None},
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 422


def test_workspace_membership_isolation_and_switching(user_client):
    client, TestingSession, member_id = user_client
    assert login(client).status_code == 200

    with TestingSession.begin() as db:
        admin = db.scalar(select(User).where(User.email == "admin@example.test"))
        admin_workspace = db.scalar(
            select(Workspace).join(WorkspaceMembership).where(
                WorkspaceMembership.user_id == admin.id
            )
        )
        admin_project = Project(
            name="Private admin project",
            workspace_id=admin_workspace.id,
            workspace_path="projects/project-private-admin",
            file_count=1,
            expanded_bytes=10,
        )
        db.add(admin_project)
        admin_workflow = Workflow(
            name="Private admin workflow",
            workspace_id=admin_workspace.id,
        )
        db.add(admin_workflow)
        db.flush()
        admin_project_id = admin_project.id
        admin_workflow_id = admin_workflow.id
        admin_run = WorkflowRun(
            workflow_id=admin_workflow.id,
            status="completed",
            source="ui",
            graph_snapshot={"nodes": [], "edges": []},
        )
        db.add(admin_run)
        db.flush()
        admin_run_id = admin_run.id

    own_workspaces = client.get("/api/workspaces")
    assert own_workspaces.status_code == 200
    assert len(own_workspaces.json()["items"]) == 1
    assert own_workspaces.json()["items"][0]["role"] == "admin"

    organization = client.post(
        "/api/organizations",
        json={"name": "Security Team"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert organization.status_code == 201
    organization_id = organization.json()["id"]

    workspace = client.post(
        "/api/workspaces",
        json={"organization_id": organization_id, "name": "Application Security"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert workspace.status_code == 201
    workspace_id = workspace.json()["id"]

    member_added = client.post(
        f"/api/organizations/{organization_id}/members",
        json={
            "email": "member@example.test",
            "workspace_id": workspace_id,
            "workspace_role": "viewer",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert member_added.status_code == 201
    assert member_added.json()["user_id"] == str(member_id)

    assert login(client, "member@example.test", "MemberPassword123!").status_code == 200
    assert client.get("/api/projects").json() == []
    hidden_project = client.get(f"/api/projects/{admin_project_id}/files")
    assert hidden_project.status_code == 404
    assert client.get("/api/workflows").json() == []
    assert client.get(f"/api/workflows/{admin_workflow_id}").status_code == 404
    assert client.get(f"/api/runs/{admin_run_id}").status_code == 404
    assert client.get(f"/api/runs/{admin_run_id}/findings").status_code == 404
    member_workspaces = client.get("/api/workspaces")
    assert member_workspaces.status_code == 200
    visible_ids = {item["id"] for item in member_workspaces.json()["items"]}
    assert workspace_id in visible_ids
    assert len(visible_ids) == 2

    switched = client.post(
        f"/api/workspaces/{workspace_id}/switch",
        headers={"Origin": "http://localhost:5173"},
    )
    assert switched.status_code == 200
    assert switched.json()["role"] == "viewer"
    active = client.get("/api/workspaces/active")
    assert active.status_code == 200
    assert active.json()["id"] == workspace_id

    denied = client.post(
        f"/api/workspaces/{organization.json()['default_workspace_id']}/switch",
        headers={"Origin": "http://localhost:5173"},
    )
    assert denied.status_code == 404


def test_workspace_membership_role_changes_removal_and_owner_transfer(user_client):
    client, TestingSession, member_id = user_client
    assert login(client).status_code == 200

    organization = client.post(
        "/api/organizations",
        json={"name": "Platform Team"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert organization.status_code == 201
    organization_id = organization.json()["id"]
    workspace_id = organization.json()["default_workspace_id"]

    added = client.post(
        f"/api/organizations/{organization_id}/members",
        json={
            "email": "member@example.test",
            "workspace_id": workspace_id,
            "workspace_role": "viewer",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert added.status_code == 201

    members = client.get(f"/api/workspaces/{workspace_id}/members")
    assert members.status_code == 200
    assert any(item["user_id"] == str(member_id) and item["role"] == "viewer" for item in members.json()["items"])

    updated = client.patch(
        f"/api/workspaces/{workspace_id}/members/{member_id}",
        json={"role": "analyst"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert updated.status_code == 200
    assert updated.json()["role"] == "analyst"

    removed_workspace = client.delete(
        f"/api/workspaces/{workspace_id}/members/{member_id}",
        headers={"Origin": "http://localhost:5173"},
    )
    assert removed_workspace.status_code == 200

    readded_workspace = client.post(
        f"/api/workspaces/{workspace_id}/members",
        json={"email": "member@example.test", "role": "editor"},
        headers={"Origin": "http://localhost:5173"},
    )
    assert readded_workspace.status_code == 201

    transferred = client.post(
        f"/api/organizations/{organization_id}/transfer-ownership",
        json={"new_owner_user_id": str(member_id), "confirm": True},
        headers={"Origin": "http://localhost:5173"},
    )
    assert transferred.status_code == 200
    assert transferred.json()["owner_user_id"] == str(member_id)

    with TestingSession() as db:
        old_owner = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == uuid.UUID(organization_id),
                OrganizationMembership.user_id == db.scalar(select(User.id).where(User.email == "admin@example.test")),
            )
        )
        new_owner = db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == uuid.UUID(organization_id),
                OrganizationMembership.user_id == member_id,
            )
        )
        assert old_owner.role == "admin"
        assert new_owner.role == "owner"

    cannot_remove_owner = client.delete(
        f"/api/organizations/{organization_id}/members/{member_id}",
        headers={"Origin": "http://localhost:5173"},
    )
    assert cannot_remove_owner.status_code == 409


def test_workspace_api_tokens_are_shown_once_scoped_and_revocable(user_client):
    client, TestingSession, member_id = user_client
    assert login(client).status_code == 200
    active = client.get("/api/workspaces/active")
    assert active.status_code == 200
    workspace_id = active.json()["id"]

    with TestingSession.begin() as db:
        member_workspace = db.scalar(
            select(Workspace).join(WorkspaceMembership).where(
                WorkspaceMembership.user_id == member_id
            )
        )
        foreign_workflow = Workflow(
            name="Foreign CI workflow",
            workspace_id=member_workspace.id,
        )
        db.add(foreign_workflow)
        db.flush()
        foreign_workflow_id = foreign_workflow.id

    created = client.post(
        f"/api/workspaces/{workspace_id}/tokens",
        json={
            "name": "GitHub Actions",
            "scopes": ["workflow:run", "run:read"],
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert created.status_code == 201
    token = created.json()["token"]
    assert token.startswith("inv_")

    listed = client.get(f"/api/workspaces/{workspace_id}/tokens")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) == 1
    assert "token" not in listed.json()["items"][0]
    token_id = listed.json()["items"][0]["id"]

    cross_workspace = client.post(
        f"/api/ci/workflows/{foreign_workflow_id}/runs",
        headers={"X-CI-Token": token},
    )
    assert cross_workspace.status_code == 401

    revoked = client.delete(
        f"/api/workspaces/{workspace_id}/tokens/{token_id}",
        headers={"Origin": "http://localhost:5173"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True
