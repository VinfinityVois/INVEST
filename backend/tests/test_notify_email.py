import smtplib

import pytest

from app.config import settings
from app.notifications.email import EmailDeliveryError, deliver_email


class DummySMTP:
    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.messages = []
        self.logged_in = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def ehlo(self):
        return True

    def starttls(self, context=None):
        return True

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, message):
        self.messages.append(message)


def test_email_requires_allowlisted_smtp(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_allowed_hosts", "")
    monkeypatch.setattr(settings, "smtp_from", "bot@example.com")
    with pytest.raises(EmailDeliveryError, match="SMTP_ALLOWED_HOSTS"):
        deliver_email({"to": ["a@example.com"]}, findings=[])

    monkeypatch.setattr(settings, "smtp_allowed_hosts", "smtp.other.com")
    with pytest.raises(EmailDeliveryError, match="SMTP_HOST is not present"):
        deliver_email({"to": ["a@example.com"]}, findings=[])


def test_email_sends_plain_summary(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_user", "user")
    monkeypatch.setattr(settings, "smtp_password", "pass")
    monkeypatch.setattr(settings, "smtp_from", "bot@example.com")
    monkeypatch.setattr(settings, "smtp_use_tls", True)
    monkeypatch.setattr(settings, "smtp_allowed_hosts", "smtp.example.com")

    created = {}

    def factory(host, port, timeout=None):
        smtp = DummySMTP(host, port, timeout)
        created["smtp"] = smtp
        return smtp

    monkeypatch.setattr(smtplib, "SMTP", factory)

    result = deliver_email(
        {
            "to": ["sec@bank.test", "sec@bank.test", "ops@bank.test"],
            "subject_template": "[{status}] {total}",
            "body_template": "{workflow} CRITICAL={critical}",
        },
        findings=[
            {"severity": "CRITICAL", "path": "App.kt", "message": "password=secret"},
        ],
        workflow_name="Gate",
    )

    assert result["delivered"] is True
    assert result["recipients"] == ["sec@bank.test", "ops@bank.test"]
    msg = created["smtp"].messages[0]
    body = msg.get_content()
    assert "CRITICAL=1" in body
    assert "password=secret" not in body
    assert "App.kt" not in body
    assert msg["From"] == "bot@example.com"
    assert "sec@bank.test" in msg["To"]
