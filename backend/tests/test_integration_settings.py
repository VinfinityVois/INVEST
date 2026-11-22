import pytest
from pydantic import ValidationError

from app.security.integrations_api import IntegrationSettingsUpdate


def test_git_repository_urls_are_canonicalized_and_deduplicated():
    payload = IntegrationSettingsUpdate(
        git_repositories=[
            "https://GitHub.com/Example/Training.git",
            "https://github.com/Example/Training",
        ]
    )
    assert payload.git_repositories == ["https://github.com/Example/Training"]


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/example/repo",
        "https://user:password@github.com/example/repo",
        "https://github.com/example/repo?token=secret",
        "https://github.com/example/repo/tree/main",
    ],
)
def test_git_allowlist_rejects_non_repository_urls(url):
    with pytest.raises(ValidationError):
        IntegrationSettingsUpdate(git_repositories=[url])


def test_telegram_chat_ids_are_validated_and_deduplicated():
    payload = IntegrationSettingsUpdate(
        telegram_chat_ids=["123456789", "-1001234567890", "123456789"]
    )
    assert payload.telegram_chat_ids == ["123456789", "-1001234567890"]


@pytest.mark.parametrize("chat_id", ["abc123", "1234", "1" * 21])
def test_telegram_chat_ids_reject_invalid_values(chat_id):
    with pytest.raises(ValidationError):
        IntegrationSettingsUpdate(telegram_chat_ids=[chat_id])


def test_webhook_hosts_are_normalized_and_deduplicated():
    payload = IntegrationSettingsUpdate(
        webhook_hosts=["Hooks.Example.com.", "hooks.example.com"]
    )
    assert payload.webhook_hosts == ["hooks.example.com"]


@pytest.mark.parametrize(
    "host",
    [
        "https://hooks.example.com",
        "*.example.com",
        "localhost",
        "hooks.example.com/path",
        "127.0.0.1",
        "service.local",
    ],
)
def test_webhook_hosts_reject_unsafe_or_non_hostname_values(host):
    with pytest.raises(ValidationError):
        IntegrationSettingsUpdate(webhook_hosts=[host])


def test_telegram_token_is_optional_and_validated():
    payload = IntegrationSettingsUpdate(telegram_bot_token="123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_123456")
    assert payload.telegram_bot_token == "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZ_123456"
    assert IntegrationSettingsUpdate(telegram_bot_token=" ").telegram_bot_token is None

    with pytest.raises(ValidationError):
        IntegrationSettingsUpdate(telegram_bot_token="not-a-token")
