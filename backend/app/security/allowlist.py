from urllib.parse import urlparse
from app.config import settings

class TargetNotAllowed(ValueError): pass

def normalize_git_target(raw_url: str) -> str:
    parsed = urlparse(raw_url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        raise TargetNotAllowed("Разрешены только HTTPS Git URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise TargetNotAllowed("Credentials, query и fragment в URL запрещены.")
    if parsed.port not in (None, 443):
        raise TargetNotAllowed("Нестандартные порты запрещены.")
    normalized = f"https://{parsed.hostname.lower()}{parsed.path.rstrip('/')}"
    if normalized not in settings.allowed_target_list:
        raise TargetNotAllowed("Цель отсутствует в ALLOWED_TARGETS.")
    return normalized
