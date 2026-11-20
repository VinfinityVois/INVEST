from types import SimpleNamespace

import pytest

from app.config import settings
from app.workflows import notifications


def test_webhook_rejects_non_https_and_unlisted_host(monkeypatch):
    monkeypatch.setattr(settings, "webhook_allowed_hosts", "hooks.example.com")
    with pytest.raises(ValueError, match="HTTPS"):
        notifications._validate_webhook_url("http://hooks.example.com/notify")
    with pytest.raises(ValueError, match="allowlist"):
        notifications._validate_webhook_url("https://evil.example/notify")


def test_webhook_rejects_private_dns_results(monkeypatch):
    monkeypatch.setattr(settings, "webhook_allowed_hosts", "hooks.example.com")
    monkeypatch.setattr(
        notifications.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("127.0.0.1", 443))],
    )
    with pytest.raises(ValueError, match="локальным"):
        notifications._validate_webhook_url("https://hooks.example.com/notify")


def test_safe_report_deduplicates_and_omits_sensitive_fields():
    report = notifications._safe_report([
        {"findings": [
            {"fingerprint": "fp-1", "rule_id": "SQLI", "severity": "HIGH", "path": "A.kt", "message": "secret-value"},
            {"fingerprint": "fp-1", "rule_id": "SQLI", "severity": "HIGH", "path": "A.kt", "message": "secret-value"},
        ]}
    ])
    assert report["finding_count"] == 1
    assert report["severity_counts"] == {"HIGH": 1}
    assert "message" not in report["findings"][0]


def test_webhook_posts_bounded_payload_without_following_redirects(monkeypatch):
    monkeypatch.setattr(settings, "webhook_allowed_hosts", "hooks.example.com")
    monkeypatch.setattr(
        notifications.socket,
        "getaddrinfo",
        lambda *args, **kwargs: [(None, None, None, None, ("93.184.216.34", 443))],
    )
    calls = {}

    class FakeResponse:
        status_code = 202

    class FakeClient:
        def __init__(self, **kwargs):
            calls["client_options"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, **kwargs):
            calls["url"] = url
            calls["payload"] = kwargs["json"]
            return FakeResponse()

    monkeypatch.setattr(notifications.httpx, "Client", FakeClient)
    result = notifications.send_webhook_notification(
        {"url": "https://hooks.example.com/notify"},
        [{"findings": [{"fingerprint": "fp", "severity": "CRITICAL", "message": "do-not-send"}]}],
        node_id="notify",
        workflow_name="Security scan",
    )
    assert result["status"] == "completed"
    assert calls["client_options"]["follow_redirects"] is False
    assert calls["payload"]["report"]["finding_count"] == 1
    assert "message" not in calls["payload"]["report"]["findings"][0]
