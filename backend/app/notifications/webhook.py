"""Safe outbound webhook delivery for workflow notifications."""
from __future__ import annotations

import ipaddress
import json
import socket
import time
from urllib.parse import urlparse

import httpcore
import httpx

from app.config import settings


class WebhookDeliveryError(RuntimeError):
    pass


def _normalize_hostname(host: str) -> str:
    return host.encode("idna").decode("ascii").lower().rstrip(".")


def _resolve_webhook_url(raw_url: str, allowed_hosts=None) -> tuple[str, str, tuple[str, ...]]:
    value = raw_url.strip()
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise WebhookDeliveryError("Webhook URL must use HTTPS.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise WebhookDeliveryError("Webhook URL must not contain credentials, query or fragment.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise WebhookDeliveryError("Webhook URL contains an invalid port.") from exc
    if port not in (None, 443):
        raise WebhookDeliveryError("Only HTTPS port 443 is allowed for webhooks.")

    raw_allowed = allowed_hosts if allowed_hosts is not None else settings.webhook_allowed_host_list
    try:
        allowed = {
            _normalize_hostname(str(item).strip())
            for item in raw_allowed
            if str(item).strip()
        }
        host = _normalize_hostname(parsed.hostname)
    except (UnicodeError, ValueError) as exc:
        raise WebhookDeliveryError("Webhook hostname is invalid.") from exc

    if host not in allowed:
        raise WebhookDeliveryError("Webhook hostname is not in NOTIFY_WEBHOOK_ALLOWED_HOSTS.")

    try:
        records = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise WebhookDeliveryError("Could not resolve webhook DNS name.") from exc
    if not records:
        raise WebhookDeliveryError("Webhook hostname has no DNS addresses.")

    validated = []
    seen = set()
    for record in records:
        try:
            ip = ipaddress.ip_address(record[4][0])
        except (IndexError, TypeError, ValueError) as exc:
            raise WebhookDeliveryError("Webhook DNS returned an invalid IP address.") from exc
        if not ip.is_global:
            raise WebhookDeliveryError("Webhook hostname resolves to a non-public IP; request blocked.")
        normalized_ip = str(ip)
        if normalized_ip not in seen:
            seen.add(normalized_ip)
            validated.append(normalized_ip)

    if not validated:
        raise WebhookDeliveryError("Webhook hostname has no usable DNS addresses.")
    return value, host, tuple(validated)


def _validate_webhook_url(raw_url: str, allowed_hosts=None) -> str:
    value, _host, _addresses = _resolve_webhook_url(raw_url, allowed_hosts)
    return value


class _PinnedIPNetworkBackend(httpcore.NetworkBackend):
    """Connect only to IPs validated before the HTTP request."""

    def __init__(self, hostname: str, addresses: tuple[str, ...], backend=None):
        self._hostname = hostname
        self._addresses = addresses
        self._backend = backend or httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        requested_host = host.decode("ascii") if isinstance(host, bytes) else str(host)
        try:
            normalized_host = _normalize_hostname(requested_host)
        except (UnicodeError, ValueError) as exc:
            raise httpcore.ConnectError("Unexpected webhook connection hostname.") from exc

        if normalized_host != self._hostname or port != 443:
            raise httpcore.ConnectError("Unexpected webhook connection destination.")

        last_error = None
        for address in self._addresses:
            try:
                return self._backend.connect_tcp(
                    host=address,
                    port=443,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc

        raise httpcore.ConnectError(
            "Could not connect to any validated webhook IP address."
        ) from last_error

    def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("Unix sockets are not allowed for webhook delivery.")

    def sleep(self, seconds):
        time.sleep(seconds)


class _PinnedIPTransport(httpx.HTTPTransport):
    """HTTPX transport whose TCP connections use the previously validated IPs."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]):
        super().__init__(trust_env=False)
        original_pool = self._pool
        ssl_context = original_pool._ssl_context
        original_pool.close()

        limits = httpx.Limits()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=_PinnedIPNetworkBackend(hostname, addresses),
        )

def _safe_findings(findings: list[dict], limit: int = 10) -> list[dict]:
    field_limits = {
        "rule_id": 120, "severity": 24, "path": 400, "message": 600,
        "recommendation": 800, "cve": 80,
    }
    safe = []
    for finding in findings[:limit]:
        if not isinstance(finding, dict):
            continue
        item = {}
        for key in ("rule_id", "severity", "path", "line", "message", "cwe", "cve", "recommendation"):
            value = finding.get(key)
            if key == "cwe" and isinstance(value, list):
                item[key] = [str(entry)[:40] for entry in value[:8]]
            elif isinstance(value, str):
                item[key] = value[:field_limits.get(key, 300)]
            elif isinstance(value, (int, float, bool)) or value is None:
                item[key] = value
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


def deliver_webhook(url: str, payload: dict, allowed_hosts=None) -> dict:
    endpoint, hostname, addresses = _resolve_webhook_url(url, allowed_hosts)
    transport = _PinnedIPTransport(hostname, addresses)
    try:
        with httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(10.0, connect=4.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            response = client.post(
                endpoint,
                json=payload,
                headers={"User-Agent": "INVEST-Security-Workflow/1.0"},
            )
        if response.is_redirect:
            raise WebhookDeliveryError("Webhook returned a redirect; redirects are disabled.")
        response.raise_for_status()
    except WebhookDeliveryError:
        raise
    except httpx.TimeoutException as exc:
        raise WebhookDeliveryError("Webhook did not respond within 10 seconds.") from exc
    except httpx.HTTPStatusError as exc:
        raise WebhookDeliveryError(f"Webhook returned HTTP {exc.response.status_code}.") from exc
    except httpx.HTTPError as exc:
        raise WebhookDeliveryError(
            "Webhook delivery failed; check the endpoint and network connection."
        ) from exc
    finally:
        transport.close()

    return {"http_status": response.status_code, "delivered": True}
