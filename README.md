# AI Security Workflow

Визуальная платформа для построения и запуска security-workflow: собственные анализаторы, AI-объяснения подтверждённых находок и уведомления.

## Архитектура

- **backend** — FastAPI, Pydantic, SQLAlchemy 2, PostgreSQL.
- **worker** — отдельный процесс, забирающий задания из очереди PostgreSQL с блокировкой `SKIP LOCKED` и heartbeat.
- **frontend** — React, Vite, TypeScript, React Flow.
- **rules/** — собственные YAML-правила детекторов.
- **data/** — локальные справочники advisories и Spring Boot managed versions.
- **eval/** — тестовые корпуса и оценка precision/recall.

## Быстрый старт

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build
```

API: http://localhost:8000/docs  
Frontend: http://localhost:5173  
Health: http://localhost:8000/health

## Источники проектов

### ZIP upload

В редакторе workflow выберите ZIP проекта. API распаковывает архив в уникальный каталог внутри `WORKSPACE_ROOT`. Ограничения:

- ZIP до 50 MiB;
- распакованный объём до 250 MiB;
- не более 5000 записей;
- коэффициент сжатия не более 100;
- отклоняются traversal/абсолютные пути, дубликаты, символьные ссылки и специальные файловые записи;
- файлы проекта не исполняются.

Endpoint: `POST /api/sources/upload` (multipart field `file`).

### Git source

Для Git-ноды задайте HTTPS URL и необязательную ветку или тег. Репозиторий должен быть явно внесён в `ALLOWED_TARGETS` в backend environment. Сопоставление выполняется по точному адресу owner/repository; URL с логином, паролем, query, fragment и нестандартным портом отклоняются.

Git clone выполняется shallow, без тегов, hooks, LFS smudge и submodules. Используется только HTTPS. Для работы Git-ноды в среде backend должен быть установлен Git. Частные репозитории и credential helper пока не поддерживаются.

Пример:

```env
WORKSPACE_ROOT=/data/workspaces
ALLOWED_TARGETS=https://github.com/example/training
```

## Текущий статус

Реализованы редактор React Flow с независимо сворачиваемыми боковыми панелями, реестр нод, валидация графа, сохранение workflow и версий, загрузка ZIP, allowlisted Git source, secrets scanner, начальный Gradle SCA-анализатор с локальным Maven advisory snapshot, Kotlin/Spring SAST (SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes, IDOR) с эталонным benchmark, устойчивая очередь PostgreSQL (`FOR UPDATE SKIP LOCKED`), отдельный worker с heartbeat и восстановлением просроченных задач.

Добавлена телеметрия последнего запуска: статус, время постановки в очередь/начала/завершения, длительность, общее число находок и распределение по severity, длительность каждого сканера и прогресс узлов. API предоставляет `/api/workflows/{workflow_id}/telemetry/latest`, `/api/runs/{run_id}/telemetry` и SSE-поток `/api/runs/{run_id}/events`. Интерфейс получает прогресс через SSE и использует polling как резервный режим.

Остаются в разработке: полноценный межпроцедурный AST/taint-анализ Kotlin SAST, Spring Boot dependency management, расширение транзитивного SCA, AI gateway и объяснения. GitHub Actions проверяет backend tests, frontend build и benchmark-наборы.

## Принципы безопасности

- Репозитории рассматриваются как недоверенные данные: никакого запуска Gradle, Maven или скриптов проекта.
- Никаких готовых security-сканеров; детекция реализуется собственными правилами.
- LLM не определяет уязвимости и не придумывает CVE — только объясняет уже найденные проблемы.
- Секреты не должны попадать в логи, API-ответы или AI-контекст в открытом виде.
- Git scanning разрешён только для точных URL из allowlist.
- ZIP/Git checkout выполняется в workspace; запуск проектных файлов запрещён.


## Security Gate

The `ci.gate` node evaluates the merged findings using explicit severity thresholds.
By default, `CRITICAL` and `HIGH` findings produce `BLOCK` and fail the workflow;
`MEDIUM`, `LOW`, and `INFO` produce `WARN`; no findings produce `PASS`.
The node accepts `block_on` and `warn_on` arrays in its configuration. The run
response and telemetry expose the decision, severity counts, and active thresholds.
Invalid severity names are rejected instead of silently weakening the policy.

The gate is deterministic and does not alter scanner findings. Workflow-scoped finding
states are stored in `finding_states`; every transition is appended to `audit_log`.
The API exposes:
- `GET /api/workflows/{id}/finding-states`
- `PUT /api/workflows/{id}/findings/{fingerprint}/state`
- `GET /api/workflows/{id}/findings/{fingerprint}/history`

Each transition requires a reason. `accepted_risk` can have an expiry date;
expired exceptions stop suppressing the finding. Active `accepted_risk` and
`false_positive` states are excluded from gate counts. A finding marked `fixed`
is not hidden if it is detected again: the worker reopens it and records the
transition in the audit log. Lifecycle controls and history are available from
each finding card in the editor.


## Finding explanations and live execution

Security findings include a concise root-cause explanation (`why_it_matters`), a remediation recommendation, CWE/CVE identifiers where available, and a short source excerpt with the affected line highlighted. Source excerpts are path-confined to the scanned workspace, size-limited, and redact common credential assignments, bearer values, and known token formats before they are returned to the UI. Secret scanner values remain masked.

The editor shows live workflow node states and an execution timeline from persisted worker events. Secrets, SCA, and SAST scanners report file-level progress (files scanned / total and current relative path); this is real scanner progress, not a simulated animation. Findings can expand an inline source preview with line numbers.
