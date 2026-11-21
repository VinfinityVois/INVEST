"""Context-aware secret scanner; never executes repository files."""
import fnmatch
import hashlib, hmac, math, re
from collections import Counter
from pathlib import Path
from app.config import settings
from app.rules_loader import RulePackError, rule_packs

MAX_FILE_BYTES=1_000_000
MAX_FILES=20_000
SKIP_DIRS={".git","node_modules",".gradle","build","dist","target",".venv"}
PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "change_me",
    "example",
    "your_key",
    "your_api_key",
    "your_token",
    "your_secret",
    "your_password",
    "xxx",
    "dummy",
    "placeholder",
    "password",
    "secret",
    "token",
}

PLACEHOLDER_PATTERN = re.compile(
    r"(?i)^(?:"
    r"\$\{[A-Za-z_][A-Za-z0-9_]*\}"
    r"|\{\{[^{}]{1,80}\}\}"
    r"|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|<[^<>]{1,80}>"
    r"|your[_-](?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret|token)(?:[_-]?here)?"
    r")$"
)
SECRET_NAME=re.compile(r"(?i)(password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret|token|authorization|bearer|credential)")
QUOTED=r"""["']([^"'\r\n]{8,})["']"""
PATTERNS=[
 ("aws_access_key",re.compile(r"\bAKIA[0-9A-Z]{16}\b"),.99,"CRITICAL","api-key"),
 ("github_token",re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),.99,"HIGH","api-key"),
 ("private_key",re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),.99,"CRITICAL","private-key"),
 ("generic_assignment",re.compile(r"""(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|passwd)\b\s*[:=]\s*["']([^"'\s]{8,})["']"""),.78,"MEDIUM","secret"),
]
def _shannon_entropy(value):
 if not value: return 0.0
 counts=Counter(value)
 return -sum((count/len(value))*math.log2(count/len(value)) for count in counts.values())

SECRET_LITERAL_ASSIGNMENT=re.compile(r"""(?i)(?P<name>[A-Za-z_][\w.-]*(?:password|passwd|api[_-]?key|access[_-]?token|client[_-]?secret|secret|token|credential|authorization)[\w.-]*)\s*[:=]\s*["'](?P<value>[^"'\r\n]{20,})["']""")
def _is_placeholder(value):
    normalized = value.strip().lower()

    if normalized in PLACEHOLDER_VALUES:
        return True

    return bool(PLACEHOLDER_PATTERN.fullmatch(normalized))
def _masked(value):
 return "[REDACTED]" if len(value)<=8 else value[:3]+"*"*min(12,len(value)-6)+value[-3:]
def _make_finding(rule_id,class_name,path,line,value,severity,confidence,end_line=None):
 digest=hmac.new(settings.app_secret_key.encode(),value.encode(),hashlib.sha256).hexdigest()
 item={"rule_id":rule_id,"class":class_name,"category":"SECRET","path":path,"line":line,"severity":severity,"confidence":confidence,"message":f"Возможный секрет ({rule_id}); значение замаскировано.","masked_value":_masked(value),"value_hash":digest,"fingerprint":hmac.new(settings.app_secret_key.encode(),f"{rule_id}:{path}:{line}:{digest}".encode(),hashlib.sha256).hexdigest()}
 if end_line is not None and end_line!=line: item["endLine"]=end_line
 return item
def scan_text(text,path, selected_rule_packs=None):
 lines = text.splitlines()
findings = []
seen = {}

def add(rule, cls, line, value, severity, confidence, end=None):
    if not value or _is_placeholder(value):
        return

    finding = _make_finding(
        rule, cls, path, line, value, severity, confidence, end
    )

    # Один и тот же секрет на одной строке — одна находка.
    # Разные секреты на одной строке сохраняются.
    dedup_key = (line, finding["value_hash"])
    existing_index = seen.get(dedup_key)

    if existing_index is None:
        seen[dedup_key] = len(findings)
        findings.append(finding)
        return

    # При совпадении оставляем вариант с более высоким приоритетом.
    severity_rank = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    existing = findings[existing_index]
    new_priority = (
        severity_rank.get(finding["severity"], 0),
        finding["confidence"],
    )
    old_priority = (
        severity_rank.get(existing["severity"], 0),
        existing["confidence"],
    )

    if new_priority > old_priority:
        findings[existing_index] = finding
 custom_patterns = []
 if selected_rule_packs is not None:
  for pack in selected_rule_packs:
   globs = pack.get("path_globs", [])
   if globs and not any(fnmatch.fnmatchcase(path, item) for item in globs):
    continue
   for item in pack.get("patterns", []):
    custom_patterns.append((item["id"], re.compile(item["regex"]), float(item.get("confidence", 0.8)), str(item.get("severity", "MEDIUM")).upper(), str(item.get("class", "secret"))))
 active_patterns = custom_patterns if selected_rule_packs is not None else PATTERNS
 for line_no,line in enumerate(lines,1):
  for rule,pattern,confidence,severity,cls in active_patterns:
   match=pattern.search(line)
   if match: add(rule,cls,line_no,match.group(1) if match.lastindex else match.group(0),severity,confidence)
  named=re.search(r"(?i)\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*"+QUOTED,line)
  if named and SECRET_NAME.search(named.group(1)):
   name=named.group(1).lower(); cls="password" if "pass" in name else ("api-key" if "key" in name else "configuration-token")
   add("named_secret_literal",cls,line_no,named.group(2),"HIGH" if "pass" in name else "MEDIUM",.88)
  bearer=re.search(r"(?i)\b(?:authorization|token)\b\s*:\s*['\"]?Bearer\s+([A-Za-z0-9._~+/=-]{8,})",line)
  if bearer: add("bearer_configuration","configuration-token",line_no,bearer.group(1),"HIGH",.94)
  entropy_match=SECRET_LITERAL_ASSIGNMENT.search(line)
  if entropy_match and SECRET_NAME.search(entropy_match.group("name")):
   candidate=entropy_match.group("value")
   already_detected=any(item["line"]==line_no for item in findings)
   if not already_detected and 20<=len(candidate)<=4096 and _shannon_entropy(candidate)>=3.5:
    add("high_entropy_secret","high-entropy-secret",line_no,candidate,"MEDIUM",.76)
  fallback=re.search(r"(?i)(?:getenv|environment\.getproperty|System\.getProperty)\s*\([^)]*\)\s*\?:\s*"+QUOTED,line)
  if fallback: add("secret_fallback","secret-fallback",line_no,fallback.group(1),"LOW",.92)
 if re.search(r"(?i)setBearerAuth\s*\(\s*\w+\s*\)|set\s*\(\s*['\"]Authorization['\"]",text):
  declarations={}
  for line_no,line in enumerate(lines,1):
   decl=re.search(r"\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*"+QUOTED,line)
   if decl: declarations[decl.group(1)]=(decl.group(2),line_no)
  concat=re.search(r"\b(?:val|var)\s+([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+\s*([A-Za-z_]\w*)",text)
  if concat and concat.group(2) in declarations and concat.group(3) in declarations:
   first,first_line=declarations[concat.group(2)]; second,second_line=declarations[concat.group(3)]
   use_line=next((i for i,line in enumerate(lines,1) if "setBearerAuth" in line and concat.group(1) in line),max(first_line,second_line))
   add("reconstructed_auth_token","recoverable-token",first_line,first+second,"MEDIUM",.91,use_line)
 return sorted(findings,key=lambda x:(x["line"],x["rule_id"]))
def scan_directory(root, on_progress=None, selected_rule_packs=None):
 root=Path(root).resolve(); results=[]; count=0
 resolved_packs = None
 if selected_rule_packs is not None:
  try:
   resolved_packs = rule_packs.resolve(selected_rule_packs, analyzer="secrets")
  except RulePackError as exc:
   raise ValueError(str(exc)) from exc
 candidates=[]
 for path in root.rglob("*"):
  if any(part in SKIP_DIRS for part in path.parts) or path.is_symlink() or not path.is_file(): continue
  try:
   if not path.resolve().is_relative_to(root): continue
  except OSError: continue
  candidates.append(path)
 candidates=candidates[:MAX_FILES]
 total_files=len(candidates)
 for path in candidates:
  count+=1
  try:
   if path.stat().st_size>MAX_FILE_BYTES: continue
   raw=path.read_bytes()
   if b"\x00" in raw[:8192]: continue
   content=raw.decode("utf-8")
  except (OSError,UnicodeDecodeError): continue
  results.extend(scan_text(content,path.relative_to(root).as_posix(),resolved_packs))
  if on_progress:
   try: on_progress({"files_scanned":count,"total_files":total_files,"current_file":path.relative_to(root).as_posix()})
   except Exception: pass
 return results
