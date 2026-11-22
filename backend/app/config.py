from urllib.parse import urlsplit

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator


class Settings(BaseSettings):
    app_env: str = "development"
    app_secret_key: str = "development-only-change-me"
    database_url: str = "sqlite:///./dev.db"
    allowed_targets: str = ""
    allowed_origins: str = ""
    workspace_root: str = "/workspace"
    master_key_file: str | None = None
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    llm_timeout_seconds: float = 300.0
    llm_max_tokens: int = 1400
    notify_webhook_allowed_hosts: str = "webhook.site"
    webhook_allowed_hosts: str | None = None
    telegram_bot_token: str | None = None
    telegram_allowed_chat_ids: str = ""
    telegram_proxy: str | None = None
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_origin_list(self) -> list[str]:
        raw_origins = self.allowed_origins.strip()

        if not raw_origins:
            if self.app_env.strip().lower() == "production":
                return []
            return ["http://localhost:5173"]

        origins = []
        seen = set()

        for item in raw_origins.split(","):
            origin = item.strip()

            if not origin or origin in {"*", "null"}:
                raise ValueError(
                    "ALLOWED_ORIGINS must contain exact HTTP(S) origins"
                )

            parsed = urlsplit(origin)

            if (
                parsed.scheme.lower() not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
                or parsed.netloc.endswith(":")
            ):
                raise ValueError(
                    "ALLOWED_ORIGINS entries must be exact HTTP(S) origins without paths or credentials"
                )

            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError(
                    "ALLOWED_ORIGINS contains an invalid port"
                ) from exc

            if port == 0:
                raise ValueError("ALLOWED_ORIGINS contains an invalid port")

            normalized = f"{parsed.scheme.lower()}://{parsed.hostname.lower()}"
            if port is not None:
                normalized = f"{normalized}:{port}"

            if normalized not in seen:
                origins.append(normalized)
                seen.add(normalized)

        if not origins:
            raise ValueError("ALLOWED_ORIGINS is empty after parsing")

        return origins

    @property
    def allowed_target_list(self) -> list[str]:
        return [
            item.strip()
            for item in (self.allowed_targets or "").split(",")
            if item.strip()
        ]

    @property
    def webhook_allowed_host_list(self) -> set[str]:
        raw = self.webhook_allowed_hosts
        if raw is None or not str(raw).strip():
            raw = self.notify_webhook_allowed_hosts
        return {
            host.strip().lower()
            for host in str(raw or "").split(",")
            if host.strip()
        }

    @property
    def telegram_allowed_chat_id_set(self) -> set[str]:
        return {
            item.strip()
            for item in (self.telegram_allowed_chat_ids or "").split(",")
            if item.strip()
        }


settings = Settings()
