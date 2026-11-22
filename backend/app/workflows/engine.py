"""Load known-good engine source and inject Telegram handler at import time."""
from __future__ import annotations

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
    "from app.notifications.telegram import TelegramDeliveryError, deliver_telegram",
)

_NOTIFY_BLOCK = '\n        elif node.type == "notify.telegram":\n            reports = [parent for parent in parents if isinstance(parent, dict)]\n            findings = []\n            report = {}\n            for item in reports:\n                if isinstance(item.get("findings"), list):\n                    findings.extend([f for f in item["findings"] if isinstance(f, dict)])\n                    report = item\n            for item in reversed(reports):\n                if item.get("explanations") is not None or item.get("explained_count") is not None:\n                    report = item\n                    if isinstance(item.get("findings"), list):\n                        findings = [f for f in item["findings"] if isinstance(f, dict)]\n                    break\n            if not findings and not report:\n                output = {\n                    "status": "blocked",\n                    "message": "Нет findings/report от предыдущего блока; подключите merge, scanner или AI explanation.",\n                }\n            else:\n                unique = {}\n                for finding in findings:\n                    key = str(finding.get("fingerprint") or (finding.get("rule_id"), finding.get("path"), finding.get("line")))\n                    unique.setdefault(key, finding)\n                findings = list(unique.values())\n                if not isinstance(report, dict):\n                    report = {}\n                report = {**report, "findings": findings, "status": report.get("status") or "completed"}\n                try:\n                    if not node.config.get("chat_ids"):\n                        output = {\n                            "status": "configuration_required",\n                            "message": "Укажите chat_ids в настройках Telegram.",\n                        }\n                    else:\n                        delivery = deliver_telegram(\n                            node.config,\n                            report=report,\n                            findings=findings,\n                            workflow_name=getattr(graph, "name", "") or "",\n                        )\n                        output = {\n                            "status": "completed",\n                            "message": "Telegram-уведомление доставлено.",\n                            "delivered": True,\n                            "chat_ids": delivery.get("chat_ids", []),\n                            "summary": {\n                                "total": delivery["summary"]["total"],\n                                "severity": delivery["summary"]["severity"],\n                            },\n                        }\n                except TelegramDeliveryError as exc:\n                    output = {"status": "failed", "message": str(exc), "delivered": False}\n'

_source = _source.replace(
    "        else:\n            output = {\"status\": \"adapter_required\"}",
    _NOTIFY_BLOCK + "        else:\n            output = {\"status\": \"adapter_required\"}",
    1,
)

exec(_source, globals())
