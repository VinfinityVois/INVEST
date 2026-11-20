import pytest
from app.security.vault import decrypt_credential, encrypt_credential, VaultError

def test_aes_gcm_roundtrip_and_record_binding(monkeypatch):
    monkeypatch.setenv("MASTER_KEY_HEX", "11" * 32)
    encrypted, nonce, _ = encrypt_credential("private-token", "cred-1", "workspace-1")
    assert decrypt_credential(encrypted, nonce, "cred-1", "workspace-1") == "private-token"
    with pytest.raises(VaultError):
        decrypt_credential(encrypted, nonce, "cred-1", "workspace-2")

def test_rejects_wrong_master_key_size(monkeypatch):
    monkeypatch.setenv("MASTER_KEY_HEX", "abcd")
    with pytest.raises(VaultError):
        encrypt_credential("secret", "cred-1", "workspace-1")
