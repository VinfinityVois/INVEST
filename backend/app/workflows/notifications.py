"""Safe, allowlisted webhook delivery for workflow notifications."""
from collections import Counter
import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

from app.config import settings


def _validate_webhook_url(value: str) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("Укажите корректный HTTPS URL webhook.")
    try:
        parsed = urlsplit(value)
        hostname = (parsed.hostname or "").lower().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Некорректный URL webhook.") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise ValueError("Webhook разрешён только по HTTPS на стандартном порту без userinfo и fragment.")
    if hostname not in settings.webhook_allowed_host_list:
        raise ValueError("Hostname webhook отсутствует в WEBHOOK_ALLOWED_HOSTS.")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)}
    except OSError as exc:
        raise ValueError("Не удалось проверить DNS-адрес webhook.") from exc
    if not addresses:
        raise ValueError("У webhook hostname нет разрешённых IP-адресов.")
    for address in addresses:
        try:
            parsed_ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ValueError("DNS webhook вернул некорректный IP-адрес.") from exc
        if not parsed_ip.is_global:
            raise ValueError("Webhook не может обращаться к локальным или приватным IP-адресам.")
    return value


def _safe_report(parents: list[dict]) -> dict:
    findings = []
    for parent in parents:
        for item in parent.get("findings", []):
            if not isinstance(item, dict):
                continue
            findings.append({
                key: item[key]
                for key in ("fingerprint", "rule_id", "severity", "category", "path", "line")
                if key in item and isinstance(item[key], (str, int, float))
            })
    unique = {}
    for finding in findings:
        key = str(finding.get("fingerprint") or (finding.get("rule_id"), finding.get("path"), finding.get("line")))
        unique.setdefault(key, finding)
    safe_findings = list(unique.values())
    counts = Counter(str(item.get("severity", "UNKNOWN")).upper() for item in safe_findings)
    return {
        "finding_count": len(safe_findings),
        "severity_counts": dict(counts),
        "findings": safe_findings[:500],
        "truncated": len(safe_findings) > 500,
    }


def send_webhook_notification(config: dict, parents: list[dict], *, node_id: str, workflow_name: str) -> dict:
    """Send a bounded metadata-only report; never forwards source snippets or secret values."""
    url = _validate_webhook_url(config.get("url"))
    report = _safe_report(parents)
    payload = {
        "event": "invest.workflow.completed",
        "workflow": str(workflow_name)[:160],
        "node_id": str(node_id)[:128],
        "report": report,
    }
    try:
        with httpx.Client(
            timeout=httpx.Timeout(8.0, connect=3.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.post(url, json=payload, headers={"User-Agent": "INVEST-Security-Workflow/1.0"})
    except httpx.HTTPError as exc:
        return {"status": "failed", "message": "Webhook transport error: " + type(exc).__name__}
    if not 200 <= response.status_code < 300:
        return {
            "status": "failed",
            "http_status": response.status_code,
            "message": "Webhook endpoint returned a non-success HTTP status.",
        }
    return {
        "status": "completed",
        "http_status": response.status_code,
        "sent_findings": report["finding_count"],
        "message": "Webhook notification delivered.",
    }
