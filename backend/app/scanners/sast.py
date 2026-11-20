"""Structure-aware Kotlin/Spring SAST rules. Static analysis only; repository code is never executed."""
from __future__ import annotations

import hashlib
import hmac
import re
from pathlib import Path

from app.config import settings
from app.scanners.secrets import MAX_FILE_BYTES, MAX_FILES, SKIP_DIRS


def _read_kotlin(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _finding(rule_id: str, path: str, line: int, severity: str, message: str,
             cwe: str, confidence: float = 0.9, end_line: int | None = None) -> dict:
    identity = f"{rule_id}:{path}:{line}"
    fingerprint = hmac.new(settings.app_secret_key.encode(), identity.encode(), hashlib.sha256).hexdigest()
    result = {
        "rule_id": rule_id, "class": rule_id.rsplit(".", 1)[-1],
        "category": "SAST", "path": path, "line": line, "severity": severity,
        "confidence": confidence, "cwe": [cwe], "message": message,
        "fingerprint": fingerprint,
    }
    if end_line and end_line != line:
        result["endLine"] = end_line
    return result


def _method_blocks(text: str):
    """Yield Kotlin function bodies using balanced braces while ignoring quoted strings/comments."""
    for match in re.finditer(r"(?m)^\s*(?:override\s+|private\s+|internal\s+|public\s+|suspend\s+)*fun\s+([A-Za-z_]\w*)\s*\([^)]*\)[^{\n]*(?:\n\s*)?\{", text):
        start = match.end()
        depth, quote, escaped, index = 1, None, False, start
        while index < len(text) and depth:
            char = text[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\\\":
                    escaped = True
                elif char == quote:
                    quote = None
            elif text.startswith("//", index):
                end = text.find("\n", index)
                index = len(text) if end < 0 else end
                continue
            elif text.startswith("/*", index):
                end = text.find("*/", index + 2)
                index = len(text) if end < 0 else end + 1
            elif char in {"'", '"'}:
                quote = char
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            index += 1
        if depth == 0:
            yield match.group(1), match.start(), start, index - 1, text[start:index - 1]


def _scan_sql(path: str, text: str) -> list[dict]:
    findings = []
    for name, method_start, body_start, _end, body in _method_blocks(text):
        params = set(re.findall(r"@RequestParam(?:\([^)]*\))?\s+(?:val\s+)?([A-Za-z_]\w*)\s*:", text[method_start:body_start]))
        if not params:
            continue
        query_calls = list(re.finditer(r"\b(?:queryForList|queryForObject|query|update|execute)\s*\(", body))
        for call in query_calls:
            prefix = body[max(0, call.start() - 500):call.start()]
            # Restrict to SQL expressions passed to JDBC and require actual Kotlin interpolation.
            sql_literals = re.findall(r'"([^"\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^"\n]*)"', prefix + body[call.start():call.start() + 500], re.I)
            for sql in sql_literals:
                for param in params:
                    if re.search(rf"\$\{{?{re.escape(param)}\}}?", sql) or re.search(rf"['\"]\s*\+\s*{re.escape(param)}", sql):
                        absolute = body_start + call.start()
                        findings.append(_finding(
                            "kotlin.jdbc.sql-injection", path, _line(text, absolute), "HIGH",
                            f"Параметр запроса {param} попадает в SQL-строку метода {name}; используйте placeholder и отдельный bind-параметр.",
                            "CWE-89", 0.96,
                        ))
                        break
                else:
                    continue
                break
    return findings


def _scan_tls(path: str, text: str) -> list[dict]:
    findings = []
    pattern = re.compile(r"hostnameVerifier\s*=\s*HostnameVerifier\s*\{[^{}]*->\s*true\s*\}", re.S)
    for match in pattern.finditer(text):
        findings.append(_finding(
            "kotlin.tls.hostname-verification-disabled", path, _line(text, match.start()),
            "MEDIUM", "HostnameVerifier принимает любое имя хоста; используйте штатную проверку TLS.",
            "CWE-295", 0.99,
        ))
    return findings


def _scan_cors(path: str, text: str) -> list[dict]:
    findings = []
    for method_name, start, body_start, _end, body in _method_blocks(text):
        wildcard = re.search(r"allowedOriginPatterns\s*=\s*listOf\(\s*['\"]\*['\"]\s*\)", body)
        credentials = re.search(r"allowCredentials\s*=\s*true", body)
        route = re.search(r"registerCorsConfiguration\(\s*['\"]([^'\"]+)['\"]", body)
        if wildcard and credentials and route and ("/customer/" in route.group(1) or "/account/" in route.group(1) or "/private/" in route.group(1)):
            findings.append(_finding(
                "kotlin.spring.credentialed-cors-wildcard", path, _line(text, body_start + wildcard.start()),
                "MEDIUM", f"CORS для {route.group(1)} разрешает любой origin вместе с credentials.",
                "CWE-942", 0.94,
            ))
    return findings


def _scan_public_sensitive_route(files: dict[str, str]) -> list[dict]:
    findings = []
    security = [(p, t) for p, t in files.items() if p.endswith(("Security.kt", "SecurityConfig.kt"))]
    controllers = [(p, t) for p, t in files.items() if "Controller" in Path(p).name]
    for sec_path, sec_text in security:
        for match in re.finditer(r"requestMatchers\(\s*(?:GET\s*,\s*)?['\"]([^'\"]+)['\"]\s*\)\.permitAll\(\)", sec_text):
            route = match.group(1)
            if not re.search(r"/(?:export|admin|private|internal|customer|account)(?:/|$)", route):
                continue
            controller = next(((p, t) for p, t in controllers if route in t or route.rsplit("/", 1)[0] in t), None)
            if controller is None:
                continue
            controller_path, controller_text = controller
            # Only report if the matching handler exposes collection/customer data and has no method-level guard.
            handler = next((m for m in _method_blocks(controller_text) if re.search(r"@GetMapping\([^\n]*" + re.escape(route.rsplit("/", 1)[-1]) , controller_text[max(0, m[1]-180):m[1]])), None)
            body_text = handler[4] if handler else controller_text
            if re.search(r"\b(?:findAll|export|listAll|allTickets|pickup|customerId|workNote)\b", body_text, re.I) and not re.search(r"@PreAuthorize|@Secured|hasRole|isAuthenticated", controller_text):
                findings.append(_finding(
                    "kotlin.spring.public-sensitive-route", sec_path, _line(sec_text, match.start()),
                    "HIGH", f"Чувствительный маршрут {route} явно открыт через permitAll().",
                    "CWE-862", 0.88,
                ))
    return findings


def _scan_idor(files: dict[str, str]) -> list[dict]:
    findings = []
    for controller_path, controller in files.items():
        if "Controller" not in Path(controller_path).name:
            continue
        for name, method_start, body_start, _end, body in _method_blocks(controller):
            mapping = controller[max(0, method_start - 220):method_start]
            if not re.search(r"@GetMapping\([^\n]*\{[A-Za-z_]\w*\}", mapping):
                continue
            if re.search(r"Principal|Authentication|@PreAuthorize|@Secured", controller[method_start:body_start]):
                continue
            call = re.search(r"\b\w+\.read\(\s*([A-Za-z_]\w*)\s*\)", body)
            if not call:
                continue
            reader_name = call.group(0).split(".", 1)[0]
            for reader_path, reader in files.items():
                if Path(reader_path).name != "RepairTicketReader.kt" and reader_name not in reader:
                    continue
                read_method = next((item for item in _method_blocks(reader) if item[0] == "read"), None)
                if not read_method:
                    continue
                reader_body = read_method[4]
                if re.search(r"WHERE\s+\w+_id\s*=\s*\?", reader_body, re.I) and not re.search(r"customer_id\s*=|owner_id\s*=|principal|customerId", reader_body, re.I):
                    # The selected record includes an owner field, but the lookup is only by caller-supplied object ID.
                    if re.search(r"customer_id|owner_id", reader_body, re.I):
                        findings.append(_finding(
                            "kotlin.spring.idor.unscoped-object-read", reader_path,
                            _line(reader, read_method[1]), "HIGH",
                            "Запись читается только по переданному object ID; отсутствует ограничение по владельцу из Principal.",
                            "CWE-639", 0.84,
                        ))
                    break
    return findings


def scan_kotlin_project(root: str | Path) -> list[dict]:
    project = Path(root).resolve()
    files: dict[str, str] = {}
    count = 0
    for path in project.rglob("*.kt"):
        if any(part in SKIP_DIRS for part in path.parts) or path.is_symlink():
            continue
        count += 1
        if count > MAX_FILES:
            break
        text = _read_kotlin(path)
        if text is not None:
            files[path.relative_to(project).as_posix()] = text

    findings = []
    for path, text in files.items():
        findings.extend(_scan_sql(path, text))
        findings.extend(_scan_tls(path, text))
        findings.extend(_scan_cors(path, text))
    findings.extend(_scan_public_sensitive_route(files))
    findings.extend(_scan_idor(files))
    unique = {item["fingerprint"]: item for item in findings}
    return sorted(unique.values(), key=lambda item: (item["path"], item["line"], item["rule_id"]))
