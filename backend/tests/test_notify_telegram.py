import httpx
import pytest

from app.config import settings
from app.notifications.telegram import TelegramDeliveryError, deliver_telegram


def test_telegram_requires_token_and_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", None)
    monkeypatch.setattr(settings, "telegram_allowed_chat_ids", "12345")
    with pytest.raises(TelegramDeliveryError, match="TELEGRAM_BOT_TOKEN"):
        deliver_telegram({"chat_ids": ["12345"]}, findings=[{"severity": "HIGH"}])

    monkeypatch.setattr(settings, "telegram_bot_token", "123:abc")
    monkeypatch.setattr(settings, "telegram_allowed_chat_ids", "")
    with pytest.raises(TelegramDeliveryError, match="TELEGRAM_ALLOWED_CHAT_IDS"):
        deliver_telegram({"chat_ids": ["12345"]}, findings=[{"severity": "HIGH"}])


def test_telegram_rejects_chat_id_outside_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", "123:abc")
    monkeypatch.setattr(settings, "telegram_allowed_chat_ids", "11111")
    with pytest.raises(TelegramDeliveryError, match="allowlist|TELEGRAM_ALLOWED"):
        deliver_telegram({"chat_ids": ["22222"]}, findings=[])


def test_telegram_sends_summary_only(monkeypatch):
    monkeypatch.setattr(settings, "telegram_bot_token", "123:abc")
    monkeypatch.setattr(settings, "telegram_allowed_chat_ids", "11111,22222")
    calls = []

    class FakeClient:
        def __init__(self, **kwargs):
            calls.append({"client": kwargs})

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, url, json, headers):
            calls.append({"url": url, "json": json, "headers": headers})
            return httpx.Response(200, json={"ok": True}, request=httpx.Request("POST", url))

    monkeypatch.setattr("app.notifications.telegram.httpx.Client", FakeClient)

    result = deliver_telegram(
        {"chat_ids": ["11111", "22222"]},
        findings=[
            {"severity": "HIGH", "path": "/secret/path", "message": "token=ghp_abc", "code_context": ["x"]},
            {"severity": "LOW"},
        ],
        workflow_name="Demo",
        run_id="run-1",
    )

    assert result["delivered"] is True
    assert result["chat_ids"] == ["11111", "22222"]
    body = calls[1]["json"]["text"]
    assert "HIGH" in body
    assert "Demo" in body
    assert "ghp_abc" not in body
    assert "/secret/path" not in body
    assert "api.telegram.org" in calls[1]["url"]
