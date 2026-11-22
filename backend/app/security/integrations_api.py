"""Workspace-scoped integration settings and encrypted credentials."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select

from app.db import SessionLocal
from app.models import AuditLog, Credential, WorkspaceIntegration
from app.security.tenancy import require_active_workspace
from app.security.vault import VaultError, encrypt_credential

router = APIRouter(prefix="/api/integrations", tags=["integrations"])

_CHAT_ID = re.compile(r"^-?\d{5,20}$")
_GIT_LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class IntegrationSettingsUpdate(BaseModel):
    git_repositories: list[str] = Field(default_factory=list, max_length=100)
    telegram_chat_ids: list[str] = Field(default_factory=list, max_length=50)
    webhook_hosts: list[str] = Field(default_factory=list, max_length=100)
    telegram_bot_token: str | None = Field(default=None, max_length=256)
    remove_telegram_bot_token: bool = False

    @field_validator("git_repositories")
    @classmethod
    def validate_git_repositories(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            parsed = urlsplit(value.strip())
            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.port is not None
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("Git repositories must be credential-free HTTPS URLs.")
            parts = [part for part in parsed.path.strip("/").split("/") if part]
            if len(parts) == 2 and parts[1].endswith(".git"):
                parts[1] = parts[1][:-4]
            if len(parts) != 2 or not all(_GIT_LABEL.fullmatch(part) for part in parts):
                raise ValueError("Git URL must point to exactly one owner/repository.")
            normalized.append(f"https://{parsed.hostname.lower()}/{parts[0]}/{parts[1]}")
        return list(dict.fromkeys(normalized))

    @field_validator("telegram_chat_ids")
    @classmethod
    def validate_chat_ids(cls, values: list[str]) -> list[str]:
        normalized = [str(value).strip() for value in values]
        if any(not _CHAT_ID.fullmatch(value) for value in normalized):
            raise ValueError("Telegram chat IDs must be numeric IDs (5–20 digits, optional leading minus).")
        return list(dict.fromkeys(normalized))

    @field_validator("webhook_hosts")
    @classmethod
    def validate_webhook_hosts(cls, values: list[str]) -> list[str]:
        normalized = []
        for value in values:
            host = value.strip().lower().rstrip(".")
            if not host or len(host) > 253 or "://" in host or "/" in host or ":" in host:
                raise ValueError("Enter a hostname only, without scheme, port, path, or wildcard.")
            try:
                ipaddress.ip_address(host)
                raise ValueError("Webhook allowlist accepts public DNS hostnames, not IP addresses.")
            except ValueError as exc:
                if str(exc).startswith("Webhook allowlist"):
                    raise
            labels = host.split(".")
            if len(labels) < 2 or host in {"localhost"} or host.endswith((".local", ".internal")) or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
                raise ValueError("Enter a valid public DNS hostname.")
            normalized.append(host)
        return list(dict.fromkeys(normalized))

    @field_validator("telegram_bot_token")
    @classmethod
    def validate_bot_token(cls, value: str | None) -> str | None:
        if value is None:
            return None
        token = value.strip()
        if not token:
            return None
        if not re.fullmatch(r"[0-9]{5,15}:[A-Za-z0-9_-]{20,}", token):
            raise ValueError("Telegram bot token has an invalid format.")
        return token


def _workspace(db, request: Request):
    try:
        return require_active_workspace(db, request, allowed_roles={"admin"})
    except HTTPException:
        raise


def _integration(db, workspace_id, provider: str) -> WorkspaceIntegration:
    row = db.scalar(
        select(WorkspaceIntegration).where(
            WorkspaceIntegration.workspace_id == workspace_id,
            WorkspaceIntegration.provider == provider,
        )
    )
    if row is None:
        row = WorkspaceIntegration(workspace_id=workspace_id, provider=provider, config={})
        db.add(row)
        db.flush()
    return row


def _bot_credential(db, workspace_id):
    return db.scalar(
        select(Credential).where(
            Credential.workspace_id == workspace_id,
            Credential.provider == "telegram_bot",
            Credential.name == "Telegram bot token",
        )
    )


def _settings_payload(db, workspace_id) -> dict:
    rows = {
        row.provider: row.config if isinstance(row.config, dict) else {}
        for row in db.scalars(
            select(WorkspaceIntegration).where(WorkspaceIntegration.workspace_id == workspace_id)
        ).all()
    }
    return {
        "git_repositories": rows.get("git", {}).get("repositories", []),
        "telegram_chat_ids": rows.get("telegram", {}).get("chat_ids", []),
        "telegram_bot_configured": _bot_credential(db, workspace_id) is not None,
        "webhook_hosts": rows.get("webhook", {}).get("hosts", []),
    }


@router.get("")
def get_integrations(request: Request):
    with SessionLocal() as db:
        workspace, _ = _workspace(db, request)
        return _settings_payload(db, workspace.id)


@router.put("")
def update_integrations(payload: IntegrationSettingsUpdate, request: Request):
    with SessionLocal() as db:
        workspace, _ = _workspace(db, request)

        git = _integration(db, workspace.id, "git")
        git.config = {"repositories": payload.git_repositories}

        telegram = _integration(db, workspace.id, "telegram")
        telegram.config = {"chat_ids": payload.telegram_chat_ids}

        webhook = _integration(db, workspace.id, "webhook")
        webhook.config = {"hosts": payload.webhook_hosts}

        credential = _bot_credential(db, workspace.id)
        if payload.remove_telegram_bot_token:
            if credential is not None:
                db.delete(credential)
        elif payload.telegram_bot_token:
            if credential is None:
                credential_id = uuid4()
                try:
                    ciphertext, nonce, key_id = encrypt_credential(
                        payload.telegram_bot_token, str(credential_id), str(workspace.id)
                    )
                except VaultError as exc:
                    raise HTTPException(status_code=503, detail="Credential vault is unavailable. Configure the platform master key once, then retry.") from exc
                db.add(Credential(
                    id=credential_id,
                    workspace_id=workspace.id,
                    name="Telegram bot token",
                    provider="telegram_bot",
                    ciphertext=ciphertext,
                    nonce=nonce,
                    key_id=key_id,
                ))
            else:
                try:
                    ciphertext, nonce, key_id = encrypt_credential(
                        payload.telegram_bot_token, str(credential.id), str(workspace.id)
                    )
                except VaultError as exc:
                    raise HTTPException(status_code=503, detail="Credential vault is unavailable. Configure the platform master key once, then retry.") from exc
                credential.ciphertext = ciphertext
                credential.nonce = nonce
                credential.key_id = key_id

        db.add(AuditLog(
            action="integrations.updated",
            entity="workspace_integrations",
            entity_id=str(workspace.id),
            details={
                "git_repository_count": len(payload.git_repositories),
                "telegram_chat_count": len(payload.telegram_chat_ids),
                "webhook_host_count": len(payload.webhook_hosts),
                "telegram_token_changed": bool(payload.telegram_bot_token or payload.remove_telegram_bot_token),
            },
        ))
        try:
            db.commit()
        except VaultError as exc:
            db.rollback()
            raise HTTPException(status_code=503, detail="Credential vault is unavailable. Configure the platform master key once, then retry.") from exc
        return _settings_payload(db, workspace.id)
