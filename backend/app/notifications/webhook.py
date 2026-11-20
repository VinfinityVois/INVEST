"""Safe outbound webhook delivery for workflow notifications."""
from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx

from app.config import settings


class WebhookDeliveryError(RuntimeError):
    pass


def _validate_webhook_url(raw_url: str) -> str:
    value = raw_url.strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise WebhookDeliveryError("Webhook URL должен использовать HTTPS.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise WebhookDeliveryError("Webhook URL не должен содержать credentials, query или fragment.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebhookDeliveryError("Webhook URL содержит некорректный порт.") from exc
    if port not in (None, 443):
        raise WebhookDeliveryError("Для webhook разрешён только HTTPS-порт 443.")
    allowed = {
        host.strip().lower().rstrip(".")
        for host in settings.notify_webhook_allowed_hosts.split(",")
        if host.strip()
    }
    host = parsed.hostname.lower().rstrip(".")
    if host not in allowed:
        raise WebhookDeliveryError("Домен webhook отсутствует в NOTIFY_WEBHOOK_ALLOWED_HOSTS.")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebhookDeliveryError("Не удалось разрешить DNS-имя webhook.") from exc
    if not addresses:
        raise WebhookDeliveryError("Webhook hostname не имеет DNS-адресов.")
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address[4][0])
        except ValueError as exc:
            raise WebhookDeliveryError("DNS webhook вернул некорректный IP-адрес.") from exc
        if not ip.is_global:
            raise WebhookDeliveryError("Webhook hostname разрешается в непубличный IP; запрос заблокирован.")
    return value


def _safe_findings(findings: list[dict], limit: int = 10) -> list[dict]:
    safe = []
    for finding in findings[:limit]:
        if not isinstance(finding, dict):
            continue
        item = {}
        for key in ("rule_id", "severity", "path", "line", "message", "cwe", "cve", "recommendation"):
            value = finding.get(key)
            if isinstance(value, (str, int, float, bool)) or value is None:
                item[key] = value
            elif key == "cwe" and isinstance(value, list):
                item[key] = [str(entry)[:40] for entry in value[:8]]
        safe.append(item)
    return safe


def build_notification_payload(report: dict, findings: list[dict] | None = None) -> dict:
    findings = findings if isinstance(findings, list) else report.get("findings", [])
    findings = [item for item in findings if isinstance(item, dict)]
    counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity", "UNKNOWN")).upper()[:24]
        counts[severity] = counts.get(severity, 0) + 1
    explanations = report.get("explanations", [])
    ai_summary = []
    if isinstance(explanations, list):
        for item in explanations[:5]:
            if not isinstance(item, dict):
                continue
            summary = " ".join(
                str(item.get(key, "")).strip()
                for key in ("root_cause", "impact", "recommendation")
                if isinstance(item.get(key), str) and item.get(key).strip()
            )
            if summary:
                ai_summary.append(summary[:700])
    payload = {
        "event": "security.workflow.completed",
        "status": report.get("status", "completed"),
        "summary": {
            "total_findings": len(findings),
            "severity": counts,
            "explained_count": report.get("explained_count", len(ai_summary)),
        },
        "top_findings": _safe_findings(findings),
        "ai_summary": ai_summary,
    }
    # Bound the serialized payload independently of the source project size.
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 48_000:
        payload["top_findings"] = payload["top_findings"][:5]
        payload["ai_summary"] = payload["ai_summary"][:2]
    return payload


def deliver_webhook(url: str, payload: dict) -> dict:
    endpoint = _validate_webhook_url(url)
    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=4.0), follow_redirects=False, trust_env=False) as client:
            response = client.post(
                endpoint,
                json=payload,
                headers={"User-Agent": "INVEST-Security-Workflow/1.0"},
            )
        if response.is_redirect:
            raise WebhookDeliveryError("Webhook вернул redirect; переход по перенаправлениям запрещён.")
        response.raise_for_status()
    except WebhookDeliveryError:
        raise
    except httpx.TimeoutException as exc:
        raise WebhookDeliveryError("Webhook не ответил за 10 секунд.") from exc
    except httpx.HTTPStatusError as exc:
        raise WebhookDeliveryError(f"Webhook вернул HTTP {exc.response.status_code}.") from exc
    except httpx.HTTPError as exc:
        raise WebhookDeliveryError("Не удалось доставить webhook; проверьте endpoint и сетевое соединение.") from exc
    return {"http_status": response.status_code, "delivered": True}
