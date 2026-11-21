import pytest
from pydantic import ValidationError

from app.config import Settings


def make_settings(**overrides):
    values = {
        "app_env": "production",
        "app_secret_key": "a" * 40,
        "database_url": "postgresql+psycopg://user:pass@db:5432/invest",
        "allowed_origins": "https://invest.example.test",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_development_allows_existing_default_settings():
    settings = Settings(
        _env_file=None,
        app_env="development",
        app_secret_key="development-only-change-me",
        database_url="sqlite:///./dev.db",
    )

    assert settings.app_env == "development"


def test_production_accepts_valid_postgresql_configuration():
    settings = make_settings()

    assert settings.app_env == "production"


def test_production_accepts_case_insensitive_environment_name():
    settings = make_settings(app_env="Production")

    assert settings.app_env == "Production"


def test_production_rejects_short_secret():
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(app_secret_key="short-secret")


def test_production_rejects_placeholder_secret():
    with pytest.raises(ValidationError, match="known placeholder"):
        make_settings(
            app_secret_key="replace-with-random-secret-" + ("x" * 40)
        )


def test_production_rejects_development_default_secret():
    with pytest.raises(ValidationError, match="at least 32 characters"):
        make_settings(app_secret_key="development-only-change-me")


def test_production_rejects_sqlite_database():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        make_settings(database_url="sqlite:///./dev.db")


def test_production_rejects_unsupported_postgresql_driver():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        make_settings(
            database_url="postgresql://user:pass@db:5432/invest"
        )


def test_production_rejects_unknown_postgresql_driver():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        make_settings(
            database_url="postgresql+unknown://user:pass@db:5432/invest"
        )


def test_development_uses_localhost_origin_by_default():
    settings = Settings(_env_file=None, app_env="development")

    assert settings.allowed_origin_list == ["http://localhost:5173"]


def test_production_accepts_explicit_multiple_origins():
    settings = make_settings(
        allowed_origins="https://invest.example.com,https://admin.example.com"
    )

    assert settings.allowed_origin_list == [
        "https://invest.example.com",
        "https://admin.example.com",
    ]


def test_production_rejects_missing_allowed_origins():
    with pytest.raises(ValidationError, match="ALLOWED_ORIGINS"):
        make_settings(allowed_origins="")


@pytest.mark.parametrize(
    "origins",
    [
        "*",
        "null",
        "https://example.com/path",
        "https://user:pass@example.com",
        "ftp://example.com",
        "https://example.com?query=1",
        "https://example.com:invalid",
    ],
)
def test_rejects_invalid_allowed_origins(origins):
    with pytest.raises(ValidationError, match="ALLOWED_ORIGINS"):
        make_settings(allowed_origins=origins)


def test_allowed_origins_are_normalized_and_deduplicated():
    settings = make_settings(
        allowed_origins=(
            "HTTPS://INVEST.EXAMPLE.COM/,"
            "https://invest.example.com"
        )
    )

    assert settings.allowed_origin_list == ["https://invest.example.com"]

def test_production_rejects_http_origins():
    with pytest.raises(ValidationError, match="HTTPS"):
        make_settings(
            allowed_origins="http://invest.example.com"
        )


def test_development_allows_http_localhost_origin():
    settings = Settings(
        _env_file=None,
        app_env="development",
        allowed_origins="http://localhost:5173",
    )

    assert settings.allowed_origin_list == [
        "http://localhost:5173"
    ]