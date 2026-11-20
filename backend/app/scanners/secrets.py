"""Небольшой собственный детектор секретов. Не запускает и не импортирует файлы проекта."""
import hashlib
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000
SKIP_DIRS = {".git", "node_modules", ".gradle", "build", "dist", "target", ".venv"}
PATTERNS = [
    ("aws_access_key", re.compile(r"\\bAKIA[0-9A-Z]{16}\\b"), 0.95, "CRITICAL"),
    ("github_token", re.compile(r"\\bgh[pousr]_[A-Za-z0-9]{20,}\\b"), 0.95, "HIGH"),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), 0.99, "CRITICAL"),
    ("generic_assignment", re.compile(r"""(?i)\\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\\b\\s*[:=]\\s*["']([^"'\\s]{8,})["']"""), 0.55, "MEDIUM"),
]
PLACEHOLDERS = ("changeme", "change-me", "example", "your_", "xxx", "dummy", "placeholder")

def _is_placeholder(value: str) -> bool:
    low = value.lower()
    return any(item in low for item in PLACEHOLDERS) or low in {"password", "secret", "token"}

def scan_text(text: str, path: str) -> list[dict]:
    findings = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for rule_id, pattern, confidence, severity in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            value = match.group(1) if rule_id == "generic_assignment" and match.lastindex else match.group(0)
            if _is_placeholder(value):
                continue
            masked = value[:4] + "*" * max(4, len(value) - 8) + value[-4:] if len(value) > 8 else "[REDACTED]"
            findings.append({
                "rule_id": rule_id, "path": path, "line": line_no,
                "severity": severity, "confidence": confidence,
                "message": f"Возможный секрет ({rule_id}); значение замаскировано.",
                "masked_value": masked,
                "value_hash": hashlib.sha256(value.encode("utf-8")).hexdigest(),
            })
    return findings

def scan_directory(root: Path) -> list[dict]:
    root = root.resolve()
    results = []
    count = 0
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        count += 1
        if count > MAX_FILES:
            break
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            raw = path.read_bytes()
            if b"\\x00" in raw[:8192]:
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        results.extend(scan_text(text, path.relative_to(root).as_posix()))
    return results
