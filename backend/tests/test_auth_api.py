import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timedelta, timezone

from app.db import Base
from app.models import LoginRateLimit, Organization, User, UserSession, Workflow, Workspace
from app.security.passwords import hash_password
import app.main as main
import app.security.api as auth_api
import app.security.tokens_api as tokens_api


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
    monkeypatch.setattr(tokens_api, "SessionLocal", TestingSession)

    with TestClient(main.app) as test_client:
        yield test_client

    engine.dispose()

def test_cors_allows_configured_development_origin(client):
    response = client.options(
        "/api/auth/login",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


def test_cors_rejects_untrusted_origin(client):
    response = client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://attacker.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


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

def test_logout_without_session_cookie_succeeds_and_clears_cookie(client):
    response = client.post(
        "/api/auth/logout",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "max-age=0" in response.headers.get("set-cookie", "").lower()


def test_logout_with_expired_session_succeeds_and_revokes_it(client):
    login = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )
    assert login.status_code == 200

    with main.SessionLocal() as db:
        session = db.query(UserSession).one()
        session.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()

    response = client.post(
        "/api/auth/logout",
        headers={"Origin": "http://localhost:5173"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
    assert "max-age=0" in response.headers.get("set-cookie", "").lower()

    with main.SessionLocal() as db:
        session = db.query(UserSession).one()
        assert session.revoked_at is not None


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


def test_ci_endpoint_does_not_accept_session_cookie_as_ci_token(client):
    with main.SessionLocal() as db:
        organization = Organization(name="CI scope test", kind="organization")
        db.add(organization)
        db.flush()
        workspace = Workspace(
            organization_id=organization.id,
            name="CI workspace",
            is_default=True,
        )
        db.add(workspace)
        db.flush()
        workflow = Workflow(name="CI workflow", workspace_id=workspace.id)
        db.add(workflow)
        db.commit()
        workflow_id = workflow.id

    client.cookies.set("invest_session", "not-a-ci-token")
    response = client.post(
        f"/api/ci/workflows/{workflow_id}/runs",
        json={},
    )
    assert response.status_code == 401




def test_login_rate_limit_persists_attempts_and_returns_retry_after(client):
    payload = {
        "email": "admin@example.test",
        "password": "WrongPassword123!",
    }
    headers = {"Origin": "http://localhost:5173"}

    for _ in range(5):
        response = client.post(
            "/api/auth/login",
            json=payload,
            headers=headers,
        )
        assert response.status_code == 401

    blocked = client.post(
        "/api/auth/login",
        json=payload,
        headers=headers,
    )

    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0
    assert blocked.json()["detail"] == (
        "Too many login attempts. Try again later."
    )

    with auth_api.SessionLocal() as db:
        email_counter = db.query(LoginRateLimit).filter_by(
            scope="email"
        ).one()
        ip_counter = db.query(LoginRateLimit).filter_by(
            scope="ip"
        ).one()

        assert email_counter.attempts == 6
        assert ip_counter.attempts == 6


def test_successful_login_clears_email_counter_but_keeps_ip_counter(client):
    success = client.post(
        "/api/auth/login",
        json={
            "email": "ADMIN@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "http://localhost:5173"},
    )

    assert success.status_code == 200

    with auth_api.SessionLocal() as db:
        email_counters = db.query(LoginRateLimit).filter_by(
            scope="email"
        ).all()
        ip_counters = db.query(LoginRateLimit).filter_by(
            scope="ip"
        ).all()

        assert email_counters == []
        assert len(ip_counters) == 1
        assert ip_counters[0].attempts == 1


def test_production_login_cookie_is_secure(client, monkeypatch):
    monkeypatch.setattr(auth_api.settings, "app_env", " production ")
    monkeypatch.setattr(
        auth_api.settings,
        "allowed_origins",
        "https://invest.example.test",
    )
    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "CorrectPassword123!",
        },
        headers={"Origin": "https://invest.example.test"},
    )

    assert response.status_code == 200
    cookie = response.headers.get("set-cookie", "").lower()
    assert "invest_session=" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie


def test_production_logout_cookie_is_secure(client, monkeypatch):
    monkeypatch.setattr(auth_api.settings, "app_env", " production ")
    monkeypatch.setattr(
        auth_api.settings,
        "allowed_origins",
        "https://invest.example.test",
    )
    response = client.post(
        "/api/auth/logout",
        headers={"Origin": "https://invest.example.test"},
    )

    assert response.status_code == 200
    cookie = response.headers.get("set-cookie", "").lower()
    assert "invest_session=" in cookie
    assert "max-age=0" in cookie
    assert "httponly" in cookie
    assert "secure" in cookie


def test_login_accepts_origin_from_configured_allowlist(client, monkeypatch):
    monkeypatch.setattr(
        main.settings,
        "allowed_origins",
        "http://localhost:5173,https://invest.example.com",
    )

    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "WrongPassword123!",
        },
        headers={"Origin": "https://invest.example.com"},
    )

    # The request passed CSRF validation and reached credential validation.
    assert response.status_code == 401


def test_login_rejects_origin_outside_configured_allowlist(client, monkeypatch):
    monkeypatch.setattr(
        main.settings,
        "allowed_origins",
        "https://invest.example.com",
    )

    response = client.post(
        "/api/auth/login",
        json={
            "email": "admin@example.test",
            "password": "WrongPassword123!",
        },
        headers={"Origin": "https://attacker.example"},
    )

    assert response.status_code == 403