"""Safe, source-linked finding presentation helpers."""
from pathlib import Path
import re

_SECRET_ASSIGNMENT = re.compile(
    r'(?i)(\b(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret|authorization)\b\s*[:=]\s*)(["\'])(.*?)(\2)'
)
_BEARER = re.compile(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}')
_LONG_TOKEN = re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b')

_REMEDIATION = {
    "sql": ("Входные данные попадают в SQL-запрос через интерполяцию или конкатенацию.",
            "Используйте параметризованный запрос / prepared statement; не собирайте SQL из пользовательского ввода."),
    "tls": ("Проверка имени TLS-сервера отключена или ослаблена.",
            "Удалите кастомный permissive HostnameVerifier и используйте стандартную проверку сертификата и hostname."),
    "cors": ("Недоверенным origin разрешён доступ вместе с credentials.",
             "Задайте точный allowlist origin; не сочетайте wildcard origin с передачей credentials."),
    "idor": ("Объект извлекается по идентификатору без проверки принадлежности текущему пользователю.",
             "Добавьте owner/tenant predicate из Principal в запрос и проверьте авторизацию на сервере."),
    "public": ("Чувствительный маршрут разрешён без аутентификации.",
               "Уберите permitAll для маршрута и добавьте проверку роли/прав доступа."),
    "secret": ("В исходном коде обнаружено значение, похожее на секрет или учётные данные.",
               "Отзовите и ротируйте секрет, удалите его из репозитория и перенесите в secret manager или защищённую переменную окружения."),
    "sca": ("Используемая версия зависимости попадает в известный уязвимый диапазон.",
            "Обновите зависимость до одной из fixed_versions и зафиксируйте безопасную версию lock-файлом."),
}


def _redact(line: str) -> str:
    line = _SECRET_ASSIGNMENT.sub(lambda m: m.group(1) + m.group(2) + "[REDACTED]" + m.group(4), line)
    line = _BEARER.sub(r"\1[REDACTED]", line)
    line = _LONG_TOKEN.sub("[REDACTED]", line)
    return line


def enrich_finding(finding: dict, root: Path) -> dict:
    """Attach explanation, remediation and a small redacted source excerpt."""
    item = dict(finding)
    rule = str(item.get("rule_id", "")).lower()
    category = str(item.get("category", "")).lower()
    key = "secret" if category == "secret" or "secret" in rule else (
        "sca" if category == "sca" or rule.startswith("sca.") else
        "sql" if "sql" in rule else
        "tls" if "tls" in rule or "hostname" in rule else
        "cors" if "cors" in rule else
        "idor" if "idor" in rule or "unscoped" in rule else
        "public" if "public-sensitive" in rule or "permitall" in rule else None
    )
    if key:
        item["why_it_matters"], item["recommendation"] = _REMEDIATION[key]
    else:
        item.setdefault("why_it_matters", item.get("message", "Сканер обнаружил совпадение с правилом безопасности. Проверьте контекст."))
        item.setdefault("recommendation", "Проверьте источник находки и примените безопасный шаблон реализации для соответствующего CWE.")

    relative = item.get("path")
    line_number = item.get("line")
    if not isinstance(relative, str) or not isinstance(line_number, int) or line_number < 1:
        item["code_context"] = []
        return item
    try:
        target = (root / relative).resolve(strict=True)
        if not target.is_relative_to(root.resolve()) or target.is_symlink() or not target.is_file():
            item["code_context"] = []
            return item
        if target.stat().st_size > 1_000_000:
            item["code_context"] = []
            return item
        lines = target.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError, ValueError):
        item["code_context"] = []
        return item

    start = max(1, line_number - 2)
    end = min(len(lines), max(int(item.get("endLine", line_number)), line_number) + 2)
    secret_context = str(item.get("category", "")).upper() == "SECRET"
    item["code_context_redacted"] = secret_context
    item["code_context"] = [
        {
            "line": number,
            "text": "[REDACTED: secret-bearing source context]" if secret_context else _redact(lines[number - 1])[:500],
            "is_finding": number == line_number,
        }
        for number in range(start, end + 1)
    ]
    item["start_line"] = start
    item["end_line"] = end
    return item
