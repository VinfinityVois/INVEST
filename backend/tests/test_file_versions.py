import hashlib

from app.security.file_versions import sha256_text, version_matches


def test_sha256_text_uses_utf8_content():
    content = "class Example: café"
    assert sha256_text(content) == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_version_matches_accepts_unchanged_snapshot():
    content = "print('safe')\n"
    assert version_matches(content, sha256_text(content))


def test_version_matches_rejects_stale_snapshot():
    original = "print('before')\n"
    changed = "print('after')\n"
    assert not version_matches(changed, sha256_text(original))
