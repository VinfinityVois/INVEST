import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret|password)(\\s*[:=]\\s*)([^\\s,;]+)"),
    re.compile(r"(?i)(AKIA[0-9A-Z]{16})"),
    re.compile(r"(?i)(gh[pousr]_[A-Za-z0-9]{20,})"),
]

def redact_text(value: str) -> str:
    result = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups == 3:
            result = pattern.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]", result)
        else:
            result = pattern.sub("[REDACTED]", result)
    return result
