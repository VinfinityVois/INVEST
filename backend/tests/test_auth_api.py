import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker

from app.db import Base
from app.models import User
from app.security.passwords import hash_password
import app.main as main
import app.security.api as auth_api


@pytest.fixture
def client(monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    with TestingSession() as db:
        db.add(
            User(
                id=uuid.uuid4(),
                email="admin@example.test",
                password_hash=hash_password("CorrectPassword123!"),
                is_active=True,
                is_admin=True,
            )
        )
        db.commit()

    monkeypatch.setattr(main, "SessionLocal", TestingSession)
    monkeypatch.setattr(auth_api, "SessionLocal", TestingSession)

    with TestClient(main.app) as test_client:
        yield test_client

    engine.dispose()


def test_private_api_rejects_anonymous_request(client):
    response = client.get("/api/ai/status")
    assert response.status_code == 401


def test_login_sets_httponly_session_cookie(client):
    response = client.post(
        "/api/auth/login",
        json={
            "email": "ADMIN@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 200
    assert response.cookies.get("invest_session")
    assert "httponly" in response.headers.get("set-cookie", "").lower()


def test_login_rejects_invalid_credentials(client):
    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "WrongPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 401
    assert "invest_session" not in response.cookies


def test_current_user_requires_valid_session(client):
    login = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert login.status_code == 200

    response = client.get("/api/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "admin@example.test"


def test_logout_revokes_session(client):
    login = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert login.status_code == 200

    response = client.post(
        "/api/auth/logout",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code == 200

    current = client.get("/api/auth/me")
    assert current.status_code == 401

def test_health_endpoints_are_public(client):
    health = client.get("/health")
    db_health = client.get("/health/db")

    assert health.status_code == 200
    assert db_health.status_code == 200


@pytest.mark.parametrize(
    "origin",
    [None, "https://attacker.example"],
)
def test_login_rejects_missing_or_untrusted_origin(client, origin):
    headers = {}
    if origin is not None:
        headers["Origin"] = origin

    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "CorrectPassword123!",
        },
        headers=headers,
    )

    assert response.status_code == 403
    assert "invest_session" not in response.cookies


def test_ci_endpoint_does_not_accept_session_cookie_as_ci_token(
    client,
    monkeypatch,
):
    from app.config import settings

    monkeypatch.setattr(
        settings,
        "ci_trigger_token",
        "dedicated-ci-secret-for-tests",
    )
    client.cookies.set("invest_session", "not-a-ci-token")

    response = client.post(
        f"/api/ci/workflows/{uuid.uuid4()}/runs",
        json={},
    )

    assert response.status_code == 401

