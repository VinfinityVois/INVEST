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
    notify_webhook_allowed_hosts: str = "webhook.site"
    ci_trigger_token: str | None = None
    template_publish_token: str | None = None
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

            scheme = parsed.scheme.lower()

            if (
                self.app_env.strip().lower() == "production"
                and scheme != "https"
            ):
                raise ValueError(
                    "ALLOWED_ORIGINS must use HTTPS in production"
                )

            host = parsed.netloc.lower()

            if (scheme == "http" and port == 80) or (
                scheme == "https" and port == 443
            ):
                host = parsed.hostname.lower()

            normalized = f"{scheme}://{host}"

            if normalized not in seen:
                origins.append(normalized)
                seen.add(normalized)

        if not origins:
            raise ValueError("ALLOWED_ORIGINS must not be empty")

        return origins
    @model_validator(mode="after")
    def validate_production_settings(self):
        origins = self.allowed_origin_list
        if self.app_env.strip().lower() == "production" and not origins:
            raise ValueError(
                "ALLOWED_ORIGINS must be explicitly configured in production"
            )
        if self.app_env.strip().lower() != "production":
            return self

        secret = self.app_secret_key.strip()
        lowered_secret = secret.lower()

        if len(secret) < 32:
            raise ValueError(
                "APP_SECRET_KEY must contain at least 32 characters in production"
            )

        unsafe_prefixes = (
            "development-only-change-me",
            "replace-with-random-secret",
            "change-me-local",
        )
        if lowered_secret.startswith(unsafe_prefixes):
            raise ValueError(
                "APP_SECRET_KEY must not contain a known placeholder in production"
            )

        database_scheme = urlsplit(self.database_url).scheme.lower()
        if database_scheme != "postgresql+psycopg":
            raise ValueError(
                "DATABASE_URL must use PostgreSQL in production"
            )

        return self

    @property
    def allowed_target_list(self) -> set[str]:
        return {x.strip().rstrip("/") for x in self.allowed_targets.split(",") if x.strip()}


settings = Settings()
