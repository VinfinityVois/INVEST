"""AES-256-GCM credential encryption with record-bound associated data."""
import os
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


class VaultError(ValueError):
    pass


def _load_or_create_master_key(path: Path) -> bytes:
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:
            pass

        if path.is_file():
            key = path.read_bytes()
        else:
            fd, temporary_name = tempfile.mkstemp(
                prefix=".invest-master-",
                suffix=".tmp",
                dir=path.parent,
            )
            try:
                with os.fdopen(fd, "wb") as temporary:
                    temporary.write(os.urandom(32))
                    temporary.flush()
                    os.fsync(temporary.fileno())
                try:
                    # Hard-link creation is atomic: concurrent API/worker startup
                    # can never observe a partially written master key.
                    os.link(temporary_name, path)
                except FileExistsError:
                    pass
            finally:
                try:
                    os.unlink(temporary_name)
                except FileNotFoundError:
                    pass

            key = path.read_bytes()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as exc:
        raise VaultError(
            "Could not access the persistent credential master-key volume."
        ) from exc

    if len(key) != 32:
        raise VaultError("Persistent credential master key must contain exactly 32 bytes.")
    return key


def _master_key() -> bytes:
    if settings.master_key_file:
        key = Path(settings.master_key_file).read_bytes()
    else:
        raw = os.environ.get("MASTER_KEY_HEX", "")
        if raw.strip():
            try:
                key = bytes.fromhex(raw)
            except ValueError as exc:
                raise VaultError("MASTER_KEY_HEX must be 64 hexadecimal characters.") from exc
        else:
            key = _load_or_create_master_key(Path("/run/invest-secrets/master.key"))

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
