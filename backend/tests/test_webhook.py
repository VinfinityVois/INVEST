import socket

import httpx
import pytest

from app.config import settings
from app.notifications.webhook import (
    WebhookDeliveryError,
    build_notification_payload,
    deliver_webhook,
)


def _public_dns(_host, _port, type=None):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]


def test_webhook_payload_contains_summary_top_findings_and_ai_but_no_source_secrets():
    report = {
        "status": "completed",
        "findings": [{
            "rule_id": "hardcoded_secret",
            "severity": "HIGH",
            "path": "src/App.kt",
            "line": 12,
            "message": "Credential exposed",
            "masked_value": "ghp_****",
            "code_context": [{"line": 12, "text": "token = [REDACTED]"}],
            "recommendation": "Rotate credential",
            "cve": None,
        }],
        "explanations": [{
            "root_cause": "A credential is hardcoded.",
            "impact": "It may be reused by an attacker.",
            "recommendation": "Move it to a secret store.",
        }],
        "explained_count": 1,
    }

    payload = build_notification_payload(report)

    assert payload["summary"]["total_findings"] == 1
    assert payload["summary"]["severity"] == {"HIGH": 1}
    assert payload["top_findings"][0]["rule_id"] == "hardcoded_secret"
    assert "masked_value" not in payload["top_findings"][0]
    assert "code_context" not in payload["top_findings"][0]
    assert "hardcoded" in payload["ai_summary"][0]


def test_webhook_rejects_unlisted_host_and_private_dns(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    ])

    with pytest.raises(WebhookDeliveryError, match="непубличный IP"):
        deliver_webhook("https://webhook.site/abc", {"event": "test"})

    with pytest.raises(WebhookDeliveryError, match="отсутствует"):
        deliver_webhook("https://example.com/hook", {"event": "test"})


def test_webhook_posts_json_without_following_redirects(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)
    calls = {}

    class FakeClient:
        def __init__(self, **kwargs):
            calls["client_options"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, json, headers):
            calls.update(url=url, payload=json, headers=headers)
            return httpx.Response(204, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.notifications.webhook.httpx.Client", FakeClient)

    result = deliver_webhook("https://webhook.site/unique-id", {"event": "test"})

    assert result == {"http_status": 204, "delivered": True}
    assert calls["payload"] == {"event": "test"}
    assert calls["client_options"]["follow_redirects"] is False
    assert calls["client_options"]["trust_env"] is False


def test_webhook_rejects_redirect_response(monkeypatch):
    monkeypatch.setattr(settings, "notify_webhook_allowed_hosts", "webhook.site")
    monkeypatch.setattr(socket, "getaddrinfo", _public_dns)

    class FakeClient:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def post(self, url, json, headers):
            return httpx.Response(302, headers={"Location": "https://example.com"}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.notifications.webhook.httpx.Client", FakeClient)

    with pytest.raises(WebhookDeliveryError, match="redirect"):
        deliver_webhook("https://webhook.site/unique-id", {"event": "test"})
