import pytest
from fastapi import HTTPException

from app.config import settings
from app.main import _require_ci_token


def test_ci_token_rejects_unconfigured_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "ci_trigger_token", None)
    with pytest.raises(HTTPException) as error:
        _require_ci_token("anything")
    assert error.value.status_code == 503


def test_ci_token_requires_exact_secret(monkeypatch):
    monkeypatch.setattr(settings, "ci_trigger_token", "a-long-random-ci-secret")
    with pytest.raises(HTTPException) as error:
        _require_ci_token("wrong")
    assert error.value.status_code == 401
    _require_ci_token("a-long-random-ci-secret")


def test_ci_token_rejects_empty_header(monkeypatch):
    monkeypatch.setattr(settings, "ci_trigger_token", "a-long-random-ci-secret")
    with pytest.raises(HTTPException) as error:
        _require_ci_token("")
    assert error.value.status_code == 401


def test_template_publish_token_is_disabled_without_configuration(monkeypatch):
    from app.main import _require_template_publish_token
    monkeypatch.setattr(settings, "template_publish_token", None)
    with pytest.raises(HTTPException) as error:
        _require_template_publish_token("anything")
    assert error.value.status_code == 503


def test_template_publish_token_requires_exact_secret(monkeypatch):
    from app.main import _require_template_publish_token
    monkeypatch.setattr(settings, "template_publish_token", "dedicated-template-publish-secret")
    with pytest.raises(HTTPException) as error:
        _require_template_publish_token("wrong")
    assert error.value.status_code == 401
    _require_template_publish_token("dedicated-template-publish-secret")
