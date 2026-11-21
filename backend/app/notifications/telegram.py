"""Allowlisted Telegram notifications (summary only)."""
from __future__ import annotations

import re

import httpx

from app.config import settings
from app.notifications.summary import build_plain_message

TELEGRAM_API = "https://api.telegram.org"
_CHAT_ID_RE = re.compile(r"^-?\d{5,20}$")


class TelegramDeliveryError(RuntimeError):
    pass


def _normalize_chat_ids(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        parts = [str(item).strip() for item in value]
    else:
        raise TelegramDeliveryError("chat_ids must be a list of numeric chat ids.")
    ids: list[str] = []
    for part in parts:
        if not part:
            continue
        if not _CHAT_ID_RE.fullmatch(part):
            raise TelegramDeliveryError(f"Invalid Telegram chat_id: {part[:32]}")
        ids.append(part)
    seen = set()
    ordered = []
    for item in ids:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def _validate_chat_ids(chat_ids: list[str]) -> list[str]:
    allowed = settings.telegram_allowed_chat_id_set
    if not allowed:
        raise TelegramDeliveryError(
            "TELEGRAM_ALLOWED_CHAT_IDS is empty; configure allowlist in .env."
        )
    rejected = [item for item in chat_ids if item not in allowed]
    if rejected:
        raise TelegramDeliveryError(
            "chat_id is not present in TELEGRAM_ALLOWED_CHAT_IDS."
        )
    if not chat_ids:
        raise TelegramDeliveryError("Specify at least one chat_id.")
    return chat_ids


def deliver_telegram(
    config: dict,
    *,
    report: dict | None = None,
    findings: list | None = None,
    workflow_name: str = "",
    run_id: str = "",
) -> dict:
    token = (settings.telegram_bot_token or "").strip()
    if not token:
        raise TelegramDeliveryError(
            "TELEGRAM_BOT_TOKEN is not configured in server environment."
        )
    if any(ch in token for ch in " \n\r\t"):
        raise TelegramDeliveryError("TELEGRAM_BOT_TOKEN has invalid format.")

    chat_ids = _validate_chat_ids(_normalize_chat_ids(config.get("chat_ids")))
    text, context = build_plain_message(
        report=report,
        findings=findings,
        workflow_name=workflow_name,
        run_id=run_id,
        template=config.get("message_template") if isinstance(config.get("message_template"), str) else None,
    )

    endpoint = f"{TELEGRAM_API}/bot{token}/sendMessage"
    delivered = []
    try:
        with httpx.Client(
            timeout=httpx.Timeout(10.0, connect=4.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            for chat_id in chat_ids:
                response = client.post(
                    endpoint,
                    json={
                        "chat_id": chat_id,
                        "text": text,
                        "disable_web_page_preview": True,
                    },
                    headers={"User-Agent": "INVEST-Security-Workflow/1.0"},
                )
                if response.is_redirect:
                    raise TelegramDeliveryError("Telegram API returned a redirect.")
                if response.status_code in {401, 403}:
                    raise TelegramDeliveryError(
                        "Telegram rejected the bot token (HTTP "
                        f"{response.status_code})."
                    )
                if response.status_code == 404:
                    raise TelegramDeliveryError("Telegram API endpoint not found.")
                if response.status_code >= 400:
                    raise TelegramDeliveryError(
                        f"Telegram API returned HTTP {response.status_code}."
                    )
                body = response.json()
                if not isinstance(body, dict) or not body.get("ok"):
                    description = ""
                    if isinstance(body, dict):
                        description = str(body.get("description", ""))[:200]
                    raise TelegramDeliveryError(
                        description or "Telegram API returned ok=false."
                    )
                delivered.append(chat_id)
    except TelegramDeliveryError:
        raise
    except httpx.TimeoutException as exc:
        raise TelegramDeliveryError("Telegram API timed out after 10 seconds.") from exc
    except httpx.HTTPError as exc:
        raise TelegramDeliveryError(
            "Telegram transport error: " + type(exc).__name__
        ) from exc

    return {
        "delivered": True,
        "chat_ids": delivered,
        "summary": {
            "total": context["total"],
            "severity": context["severity"],
        },
    }
