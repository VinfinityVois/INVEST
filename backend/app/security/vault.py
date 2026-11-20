"""AES-256-GCM credential encryption with record-bound associated data."""
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import settings

class VaultError(ValueError): pass

def _master_key() -> bytes:
    if settings.master_key_file:
        key = Path(settings.master_key_file).read_bytes()
    else:
        raw = os.environ.get("MASTER_KEY_HEX", "")
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise VaultError("MASTER_KEY_HEX must be 64 hexadecimal characters.") from exc
    if len(key) != 32:
        raise VaultError("Master key must contain exactly 32 bytes.")
    return key

def encrypt_credential(value: str, credential_id: str, workspace_id: str, key_id: str = "v1") -> tuple[bytes, bytes, str]:
    nonce = os.urandom(12)
    aad = f"{credential_id}:{workspace_id}".encode()
    ciphertext = AESGCM(_master_key()).encrypt(nonce, value.encode("utf-8"), aad)
    return ciphertext, nonce, key_id

def decrypt_credential(ciphertext: bytes, nonce: bytes, credential_id: str, workspace_id: str) -> str:
    aad = f"{credential_id}:{workspace_id}".encode()
    try:
        return AESGCM(_master_key()).decrypt(nonce, ciphertext, aad).decode("utf-8")
    except Exception as exc:
        raise VaultError("Credential authentication failed.") from exc
