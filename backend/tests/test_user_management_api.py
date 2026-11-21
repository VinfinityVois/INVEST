import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import User, UserSession
from app.security.passwords import hash_password, verify_password
from app.security.sessions import create_session
import app.main as main
import app.security.api as auth_api
import app.security.users_api as users_api


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
        db.commit()
        member_id = member.id

    monkeypatch.setattr(main, "SessionLocal", TestingSession)
    monkeypatch.setattr(auth_api, "SessionLocal", TestingSession)
    monkeypatch.setattr(users_api, "SessionLocal", TestingSession)

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
