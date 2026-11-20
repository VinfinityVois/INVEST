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
                elif char == "\\":
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
    lines = text.splitlines()
    for index, line in enumerate(lines):
        params = set(re.findall(r"@RequestParam(?:\([^)]*\))?\s+(?:val\s+)?([A-Za-z_]\w*)\s*:", line))
        if not params:
            continue
        chunk_lines = []
        for candidate in lines[index + 1:index + 10]:
            if re.search(r"^\s*(?:@\w+|(?:override\s+)?fun\s+)", candidate):
                break
            chunk_lines.append(candidate)
        chunk = "\n".join(chunk_lines)
        if not re.search(r"\b(?:queryForList|queryForObject|query|update|execute)\s*\(", chunk):
            continue
        sql_literals = re.findall(r'"([^"\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^"\n]*)"', chunk, re.I)
        for sql in sql_literals:
            vulnerable = next((param for param in params if re.search(rf"\$\{{?{re.escape(param)}\}}?", sql)), None)
            if vulnerable:
                findings.append(_finding(
                    "kotlin.jdbc.sql-injection", path, index + 1, "HIGH",
                    f"Параметр запроса {vulnerable} попадает в SQL-строку; используйте placeholder и отдельный bind-параметр.",
                    "CWE-89", 0.96,
                ))
                break
    return findings


_TAINT_SOURCE_ANNOTATIONS = re.compile(
    r"@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue)\b"
)
_SQL_SINK_CALL = re.compile(r"\b(?:queryForList|queryForObject|query|update|execute)\s*\(\s*([^,\n]+)", re.I)
_SQL_CONTEXT = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\b", re.I)


def _split_call_arguments(value: str) -> list[str]:
    """Split a Kotlin argument list without splitting nested calls or quoted commas."""
    parts, start, depth, quote, escaped = [], 0, 0, None, False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(value[start:index].strip())
            start = index + 1
    tail = value[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _method_parameters(signature: str) -> list[tuple[str, bool]]:
    match = re.search(r"\bfun\s+[A-Za-z_]\w*\s*\((.*)\)", signature, re.S)
    if not match:
        return []
    parameters = []
    for part in _split_call_arguments(match.group(1)):
        name = re.search(r"(?:\b(?:val|var)\s+)?([A-Za-z_]\w*)\s*:", part)
        if name:
            parameters.append((name.group(1), bool(_TAINT_SOURCE_ANNOTATIONS.search(part))))
    return parameters


def _is_sql_safe_conversion(expression: str, tainted_names: set[str]) -> bool:
    """Only conversions that constrain input to a non-SQL token type are safe."""
    if not any(re.search(rf"\b{re.escape(name)}\b", expression) for name in tainted_names):
        return False
    numeric = re.search(
        r"\.\s*(?:toByte|toShort|toInt|toLong|toFloat|toDouble|"
        r"toByteOrNull|toShortOrNull|toIntOrNull|toLongOrNull|toFloatOrNull|toDoubleOrNull)\s*\(",
        expression,
    )
    uuid = re.search(r"\bUUID\s*\.\s*fromString\s*\(", expression)
    return bool(numeric or uuid)


def _scan_interprocedural_sql_taint(path: str, text: str, project_files: dict[str, str] | None = None) -> list[dict]:
    """Bounded same-project Kotlin taint analysis across direct function calls.

    This is deliberately conservative and lexical (not a Kotlin compiler AST):
    annotated HTTP parameters and request accessors are tracked through local
    assignments and direct calls, including helpers declared in other .kt files.
    """
    sources = project_files or {path: text}
    methods = []
    expression_pattern = re.compile(
        r"(?m)^\s*(?:(?:override|private|internal|public|suspend)\s+)*"
        r"fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
        r"(?:\:\s*[^=\n]+)?\s*=\s*([^\n]*)"
    )
    for source_path, source_text in sources.items():
        block_methods = list(_method_blocks(source_text))
        block_starts = {item[1] for item in block_methods}
        for name, start, body_start, _end, body in block_methods:
            parameters = _method_parameters(source_text[start:body_start])
            methods.append({
                "name": name, "path": source_path, "source": source_text,
                "body_start": body_start, "body": body, "parameters": parameters,
                "tainted_parameters": {i for i, (_param, source) in enumerate(parameters) if source},
            })
        for match in expression_pattern.finditer(source_text):
            if match.start() in block_starts:
                continue
            expression = match.group(3).strip()
            if not expression:
                continue
            parameters = _method_parameters(f"fun {match.group(1)}({match.group(2)})")
            methods.append({
                "name": match.group(1), "path": source_path, "source": source_text,
                "body_start": match.start(3), "body": expression, "parameters": parameters,
                "tainted_parameters": {i for i, (_param, source) in enumerate(parameters) if source},
            })

    if not methods:
        return []
    by_name: dict[str, list[int]] = {}
    for index, method in enumerate(methods):
        by_name.setdefault(method["name"], []).append(index)

    tainted_arguments = [set(method["tainted_parameters"]) for method in methods]
    tainted_variables: list[set[str]] = [set() for _ in methods]
    interprocedural_arguments: list[set[int]] = [set() for _ in methods]
    # Fixed-point propagation is bounded by both graph size and iteration count.
    for _iteration in range(min(16, len(methods) + 1)):
        changed = False
        for index, method in enumerate(methods):
            variables = {
                name for position, (name, _source) in enumerate(method["parameters"])
                if position in tainted_arguments[index]
            }
            body = method["body"]
            for _pass in range(8):
                before = len(variables)
                for assignment in re.finditer(r"\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*([^\n;]+)", body):
                    variable, expression = assignment.groups()
                    request_source = re.search(
                        r"\brequest\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\(",
                        expression,
                    )
                    carries_taint = any(
                        re.search(rf"\b{re.escape(item)}\b", expression) for item in variables
                    )
                    safely_converted = _is_sql_safe_conversion(expression, variables)
                    if request_source or (carries_taint and not safely_converted):
                        variables.add(variable)
                if len(variables) == before:
                    break
            if variables != tainted_variables[index]:
                tainted_variables[index] = variables
                changed = True

            for call in re.finditer(r"\b([A-Za-z_]\w*)\s*\(((?:[^()\n]|\([^()\n]*\))*)\)", body):
                targets = by_name.get(call.group(1), [])
                if not targets:
                    continue
                args = _split_call_arguments(call.group(2))
                for target in targets:
                    for position, argument in enumerate(args[:len(methods[target]["parameters"])]):
                        request_source = bool(re.search(
                            r"\brequest\s*\.\s*(?:getParameter|getHeader|getQueryString)\s*\(",
                            argument,
                        ))
                        carries_taint = any(
                            re.search(rf"\b{re.escape(item)}\b", argument) for item in variables
                        )
                        is_tainted = request_source or (
                            carries_taint and not _is_sql_safe_conversion(argument, variables)
                        )
                        if is_tainted:
                            if position not in tainted_arguments[target]:
                                tainted_arguments[target].add(position)
                                changed = True
                            if position not in methods[target]["tainted_parameters"]:
                                interprocedural_arguments[target].add(position)
        if not changed:
            break

    findings = []
    for index, method in enumerate(methods):
        if not interprocedural_arguments[index]:
            continue
        variables = tainted_variables[index]
        body = method["body"]
        for sink in _SQL_SINK_CALL.finditer(body):
            expression = sink.group(1).strip()
            reaches_sink = any(
                re.search(rf"\$\{{?{re.escape(item)}\}}?", expression)
                or re.search(rf"\b{re.escape(item)}\b", expression)
                for item in variables
            )
            if not reaches_sink:
                continue
            findings.append(_finding(
                "kotlin.taint.interprocedural-sql-injection", method["path"],
                _line(method["source"], method["body_start"] + sink.start()), "HIGH",
                "Данные HTTP-запроса проходят через вызов функции и попадают в SQL-выражение. "
                "Используйте bind-параметры вместо конкатенации или Kotlin string templates.",
                "CWE-89", 0.91,
            ))
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
        for mapping in re.finditer(r"@GetMapping\([^\n]*\{([A-Za-z_]\w*)\}[^\n]*\)\s*\n\s*fun\s+([A-Za-z_]\w*)\s*\(([^)]*)\)([^\n]*)(?:\n(?P<body>(?:(?!\s*@(?:Get|Post|Put|Delete)Mapping).)*))?", controller, re.S):
            object_id, _method, params, _return, body = mapping.groups()
            body = body or ""
            if re.search(r"Principal|Authentication|@PreAuthorize|@Secured", params + body):
                continue
            call = re.search(r"\b\w+\.read\(\s*" + re.escape(object_id) + r"\s*\)", body)
            if not call:
                continue
            reader_name = call.group(0).split(".", 1)[0]
            for reader_path, reader in files.items():
                if Path(reader_path).name not in {"RepairTicketReader.kt", "TicketReader.kt"} and reader_name not in reader:
                    continue
                read_match = re.search(r"(?m)^\s*fun\s+read\s*\([^)]*\)[^=\n]*=?(?P<body>.*?)(?=^\s*fun\s+|\Z)", reader, re.S)
                if not read_match:
                    continue
                reader_body = read_match.group("body")
                where_clause = re.split(r"\bWHERE\b", reader_body, flags=re.I)[-1]
                has_id_lookup = re.search(r"\bWHERE\s+\w+_id\s*=\s*\?", reader_body, re.I)
                has_owner_filter = re.search(r"\b(?:customer_id|owner_id)\s*=|principal|customerId", where_clause, re.I)
                selects_owner = re.search(r"customer_id|owner_id", reader_body, re.I)
                if has_id_lookup and not has_owner_filter and selects_owner:
                    findings.append(_finding(
                        "kotlin.spring.idor.unscoped-object-read", reader_path,
                        _line(reader, read_match.start()), "HIGH",
                        "Запись читается только по переданному object ID; отсутствует ограничение по владельцу из Principal.",
                        "CWE-639", 0.84,
                    ))
                break
    return findings

def scan_kotlin_project(root: str | Path, on_progress=None) -> list[dict]:
    project = Path(root).resolve()
    candidates = [
        path for path in project.rglob("*.kt")
        if not any(part in SKIP_DIRS for part in path.parts) and not path.is_symlink()
    ][:MAX_FILES]
    files: dict[str, str] = {}
    total_files = len(candidates)
    for count, path in enumerate(candidates, 1):
        text = _read_kotlin(path)
        if text is not None:
            files[path.relative_to(project).as_posix()] = text
        if on_progress:
            try:
                on_progress({"files_scanned": count, "total_files": total_files, "current_file": path.relative_to(project).as_posix()})
            except Exception:
                pass

    findings = []
    for path, text in files.items():
        findings.extend(_scan_sql(path, text))
        findings.extend(_scan_interprocedural_sql_taint(path, text, files))
        findings.extend(_scan_tls(path, text))
        findings.extend(_scan_cors(path, text))
    findings.extend(_scan_public_sensitive_route(files))
    findings.extend(_scan_idor(files))
    unique = {item["fingerprint"]: item for item in findings}
    return sorted(unique.values(), key=lambda item: (item["path"], item["line"], item["rule_id"]))
