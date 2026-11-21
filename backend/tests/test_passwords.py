import pytest

from app.security.passwords import (
    hash_password,
    password_hash_needs_rehash,
    verify_password,
)


def test_password_hash_uses_argon2id():
    password_hash = hash_password("Correct-Horse-Battery-42")
    assert password_hash.startswith("$argon2id$")
    assert verify_password("Correct-Horse-Battery-42", password_hash)


def test_same_password_gets_different_hashes():
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second
    assert verify_password("same-password", first)
    assert verify_password("same-password", second)


def test_wrong_password_is_rejected():
    password_hash = hash_password("correct-password")
    assert not verify_password("wrong-password", password_hash)


@pytest.mark.parametrize("password", ["", None, 123])
def test_hash_rejects_empty_or_non_string_password(password):
    with pytest.raises(ValueError):
        hash_password(password)


def test_hash_rejects_oversized_password():
    with pytest.raises(ValueError):
        hash_password("x" * 1025)


def test_verify_rejects_malformed_hash():
    assert not verify_password("password", "not-an-argon2-hash")


def test_verify_rejects_non_string_arguments():
    assert not verify_password(None, "hash")
    assert not verify_password("password", None)


def test_current_hash_does_not_need_rehash():
    password_hash = hash_password("password")
    assert not password_hash_needs_rehash(password_hash)


def test_malformed_hash_needs_rehash():
    assert password_hash_needs_rehash("invalid-hash")
