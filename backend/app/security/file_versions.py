"""Content-version helpers for safe project file updates."""
import hashlib


def sha256_text(content: str) -> str:
    """Return the SHA-256 digest of a UTF-8 text snapshot."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def version_matches(content: str, expected_sha256: str) -> bool:
    """Compare a client snapshot token with the current file contents."""
    return sha256_text(content) == expected_sha256
