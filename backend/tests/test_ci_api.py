import hashlib
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.security.tokens_api import require_workspace_api_token, token_digest


class FakeTokenSession:
    def __init__(self, token=None, owner=None):
        self.token = token
        self.owner = owner
        self.flushed = False
        self.scalar_calls = 0

    def scalar(self, statement):
        self.scalar_calls += 1
        return self.token if self.scalar_calls == 1 else "admin"

    def get(self, model, identifier):
        return self.owner

    def flush(self):
        self.flushed = True


def test_workspace_token_rejects_unknown_or_revoked_token():
    db = FakeTokenSession()
    with pytest.raises(HTTPException) as error:
        require_workspace_api_token(db, "inv_unknown", uuid4(), "workflow:run")
    assert error.value.status_code == 401


def test_workspace_token_requires_declared_scope():
    token = SimpleNamespace(
        scopes=["run:read"],
        expires_at=None,
        user_id=uuid4(),
        last_used_at=None,
    )
    db = FakeTokenSession(token, SimpleNamespace(id=token.user_id, is_active=True))
    with pytest.raises(HTTPException) as error:
        require_workspace_api_token(db, "inv_valid", uuid4(), "workflow:run")
    assert error.value.status_code == 403


def test_workspace_token_rejects_expired_token():
    token = SimpleNamespace(
        scopes=["run:read"],
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        user_id=uuid4(),
        last_used_at=None,
    )
    db = FakeTokenSession(token, SimpleNamespace(is_active=True))
    with pytest.raises(HTTPException) as error:
        require_workspace_api_token(db, "inv_expired", uuid4(), "run:read")
    assert error.value.status_code == 401


def test_workspace_token_rejects_inactive_owner():
    token = SimpleNamespace(
        scopes=["run:read"],
        expires_at=None,
        user_id=uuid4(),
        last_used_at=None,
    )
    db = FakeTokenSession(token, SimpleNamespace(is_active=False))
    with pytest.raises(HTTPException) as error:
        require_workspace_api_token(db, "inv_inactive", uuid4(), "run:read")
    assert error.value.status_code == 401


def test_workspace_token_updates_last_used_and_returns_token():
    token = SimpleNamespace(
        scopes=["workflow:run"],
        expires_at=None,
        user_id=uuid4(),
        last_used_at=None,
    )
    db = FakeTokenSession(token, SimpleNamespace(id=token.user_id, is_active=True))
    resolved = require_workspace_api_token(db, "inv_valid", uuid4(), "workflow:run")
    assert resolved is token
    assert token.last_used_at is not None
    assert db.flushed is True


def test_token_digest_is_one_way_sha256():
    assert token_digest("inv_secret") == hashlib.sha256(b"inv_secret").hexdigest()
