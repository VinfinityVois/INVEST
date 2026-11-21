"""Allowlisted SMTP email notifications (summary only, plain text)."""
from __future__ import annotations

import re
import smtplib
import ssl
from email.message import EmailMessage

from app.config import settings
from app.notifications.summary import (
    DEFAULT_SUBJECT_TEMPLATE,
    build_plain_message,
    render_template,
)

_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,63}$")


class EmailDeliveryError(RuntimeError):
    pass


def _normalize_recipients(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.replace(";", ",").split(",")]
    elif isinstance(value, list):
        parts = [str(item).strip() for item in value]
    else:
        raise EmailDeliveryError("to must be a list of email addresses.")
    emails: list[str] = []
    for part in parts:
        if not part:
            continue
        if len(part) > 254 or not _EMAIL_RE.fullmatch(part):
            raise EmailDeliveryError(f"Invalid recipient email: {part[:64]}")
        emails.append(part.lower())
    seen = set()
    ordered = []
    for item in emails:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def _validate_smtp_settings() -> tuple[str, int, str | None, str | None, str, bool]:
    host = (settings.smtp_host or "").strip().lower().rstrip(".")
    if not host:
        raise EmailDeliveryError("SMTP_HOST is not configured in server environment.")
    allowed = settings.smtp_allowed_host_set
    if not allowed:
        raise EmailDeliveryError("SMTP_ALLOWED_HOSTS is empty; configure allowlist in .env.")
    if host not in allowed:
        raise EmailDeliveryError("SMTP_HOST is not present in SMTP_ALLOWED_HOSTS.")
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        raise EmailDeliveryError("Local SMTP hosts are not allowed.")
    try:
        port = int(settings.smtp_port)
    except (TypeError, ValueError) as exc:
        raise EmailDeliveryError("SMTP_PORT must be an integer.") from exc
    if port not in {25, 465, 587, 2525}:
        raise EmailDeliveryError("SMTP_PORT must be one of 25, 465, 587, 2525.")
    mail_from = (settings.smtp_from or "").strip()
    if not mail_from or not _EMAIL_RE.fullmatch(mail_from):
        raise EmailDeliveryError("SMTP_FROM must be a valid email address.")
    user = (settings.smtp_user or "").strip() or None
    password = (settings.smtp_password or "").strip() or None
    use_tls = bool(settings.smtp_use_tls)
    return host, port, user, password, mail_from, use_tls


def deliver_email(
    config: dict,
    *,
    report: dict | None = None,
    findings: list | None = None,
    workflow_name: str = "",
    run_id: str = "",
) -> dict:
    host, port, user, password, mail_from, use_tls = _validate_smtp_settings()
    recipients = _normalize_recipients(config.get("to"))
    if not recipients:
        raise EmailDeliveryError("Specify at least one recipient in to.")

    body, context = build_plain_message(
        report=report,
        findings=findings,
        workflow_name=workflow_name,
        run_id=run_id,
        template=config.get("body_template") if isinstance(config.get("body_template"), str) else None,
    )
    subject = render_template(
        config.get("subject_template") if isinstance(config.get("subject_template"), str) else None,
        context,
        DEFAULT_SUBJECT_TEMPLATE,
    )[:200]

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = mail_from
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    try:
        if port == 465:
            context_ssl = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=10, context=context_ssl) as smtp:
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.ehlo()
                if use_tls:
                    context_ssl = ssl.create_default_context()
                    smtp.starttls(context=context_ssl)
                    smtp.ehlo()
                if user and password:
                    smtp.login(user, password)
                smtp.send_message(message)
    except EmailDeliveryError:
        raise
    except smtplib.SMTPAuthenticationError as exc:
        raise EmailDeliveryError("SMTP authentication failed.") from exc
    except smtplib.SMTPException as exc:
        raise EmailDeliveryError("SMTP delivery failed: " + type(exc).__name__) from exc
    except OSError as exc:
        raise EmailDeliveryError("SMTP connection failed: " + type(exc).__name__) from exc

    return {
        "delivered": True,
        "recipients": recipients,
        "summary": {
            "total": context["total"],
            "severity": context["severity"],
        },
    }
