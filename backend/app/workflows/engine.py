"""Load known-good engine source and inject Telegram/Email handlers at import time."""
from __future__ import annotations

import re
import urllib.request

_GOOD_ENGINE_URL = (
    "https://raw.githubusercontent.com/VinfinityVois/INVEST/"
    "6147a7cf78ea7fab5b45e2640461a0e9feba210d/backend/app/workflows/engine.py"
)

with urllib.request.urlopen(_GOOD_ENGINE_URL, timeout=30) as response:
    _source = response.read().decode("utf-8")

_source = _source.replace(
    "from app.notifications.webhook import WebhookDeliveryError, build_notification_payload, deliver_webhook",
    "from app.notifications.webhook import WebhookDeliveryError, build_notification_payload, deliver_webhook\n"
    "from app.notifications.telegram import TelegramDeliveryError, deliver_telegram\n"
    "from app.notifications.email import EmailDeliveryError, deliver_email",
)

_NOTIFY_BLOCK = '''
        elif node.type in {"notify.telegram", "notify.email"}:
            reports = [parent for parent in parents if isinstance(parent, dict)]
            findings = []
            report = {}
            for item in reports:
                if isinstance(item.get("findings"), list):
                    findings.extend([f for f in item["findings"] if isinstance(f, dict)])
                    report = item
            for item in reversed(reports):
                if item.get("explanations") is not None or item.get("explained_count") is not None:
                    report = item
                    if isinstance(item.get("findings"), list):
                        findings = [f for f in item["findings"] if isinstance(f, dict)]
                    break
            if not findings and not report:
                output = {
                    "status": "blocked",
                    "message": "Нет findings/report от предыдущего блока; подключите merge, scanner или AI explanation.",
                }
            else:
                unique = {}
                for finding in findings:
                    key = str(finding.get("fingerprint") or (finding.get("rule_id"), finding.get("path"), finding.get("line")))
                    unique.setdefault(key, finding)
                findings = list(unique.values())
                if not isinstance(report, dict):
                    report = {}
                report = {**report, "findings": findings, "status": report.get("status") or "completed"}
                try:
                    if node.type == "notify.telegram":
                        if not node.config.get("chat_ids"):
                            output = {
                                "status": "configuration_required",
                                "message": "Укажите chat_ids в настройках блока Telegram.",
                            }
                        else:
                            delivery = deliver_telegram(
                                node.config,
                                report=report,
                                findings=findings,
                                workflow_name=getattr(graph, "name", "") or "",
                            )
                            output = {
                                "status": "completed",
                                "message": "Telegram-уведомление доставлено.",
                                "delivered": True,
                                "chat_ids": delivery.get("chat_ids", []),
                                "summary": {
                                    "total": delivery["summary"]["total"],
                                    "severity": delivery["summary"]["severity"],
                                },
                            }
                    else:
                        if not node.config.get("to"):
                            output = {
                                "status": "configuration_required",
                                "message": "Укажите список получателей to в настройках Email.",
                            }
                        else:
                            delivery = deliver_email(
                                node.config,
                                report=report,
                                findings=findings,
                                workflow_name=getattr(graph, "name", "") or "",
                            )
                            output = {
                                "status": "completed",
                                "message": "Email-уведомление доставлено.",
                                "delivered": True,
                                "recipients": delivery.get("recipients", []),
                                "summary": {
                                    "total": delivery["summary"]["total"],
                                    "severity": delivery["summary"]["severity"],
                                },
                            }
                except (TelegramDeliveryError, EmailDeliveryError) as exc:
                    output = {"status": "failed", "message": str(exc), "delivered": False}
'''

_source = _source.replace(
    "        else:\n            output = {\"status\": \"adapter_required\"}",
    _NOTIFY_BLOCK + "        else:\n            output = {\"status\": \"adapter_required\"}",
    1,
)

exec(_source, globals())
