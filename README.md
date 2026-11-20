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

### Библиотека проектов и ZIP upload

В левой панели доступна постоянная библиотека проектов. Добавление ZIP создаёт отдельную запись и каталог в `WORKSPACE_ROOT/projects`. Проект можно открыть прямо в площадке (дерево файлов + безопасный текстовый просмотр), искать текст по исходникам с переходом к совпавшей строке, редактировать поддерживаемые текстовые файлы, обновить новой версией ZIP, переименовать или удалить. При открытии путь проекта автоматически устанавливается в блок `Project source` текущего workflow; граф получает имя проекта.

Ограничения архива:

- ZIP до **300 MiB**;
- распакованный объём до **2 GiB**;
- не более 20000 записей;
- коэффициент сжатия не более 100;
- отклоняются traversal/абсолютные пути, дубликаты, символьные ссылки, специальные и зашифрованные файловые записи;
- файлы проекта не исполняются;
- просмотр текстового файла ограничен 1 MiB и 300 строками на запрос; секретоподобные значения маскируются;
- встроенное редактирование доступно только для allowlist текстовых расширений и файлов до 1 MiB; потенциально секретные файлы/значения остаются read-only, а сохранение блокируется во время активного workflow;
- поиск по содержимому ограничен 3000 текстовыми файлами по 512 KiB, выдача — 100 совпадений; файлы и строки с секретоподобными значениями пропускаются.
- встроенный редактор показывает номера строк, подсветку синтаксиса в режиме просмотра и предоставляет поиск/замену в открытом файле; замены применяются локально до явного сохранения.

Project API:
- `GET /api/projects` — список библиотеки;
- `POST /api/projects` — добавить проект из ZIP (multipart field `file`);
- `PUT /api/projects/{id}/archive` — обновить содержимое проекта из ZIP;
- `PATCH /api/projects/{id}` — переименовать;
- `DELETE /api/projects/{id}` — удалить запись и файлы;
- `GET /api/projects/{id}/download` — скачать безопасный ZIP проекта (до 1 GiB; без `.git`, symlink и потенциально секретных файлов/значений; большие текстовые файлы свыше 1 MiB исключаются, если их нельзя безопасно проверить);
- `GET /api/projects/{id}/file/download?path=...` — скачать отдельный файл (до 100 MiB; текстовые файлы проверяются на секреты и ограничены 1 MiB);
- `GET /api/projects/{id}/files` — дерево файлов;
- `GET /api/projects/{id}/file?path=...` — безопасный просмотр текстового файла;
- `PUT /api/projects/{id}/file?path=...` — безопасное сохранение поддерживаемого текстового файла (JSON `{ "content": "..." }`);
- `GET /api/projects/{id}/search?q=...` — поиск по содержимому исходников.

Для разового источника без добавления в библиотеку по-прежнему доступен `POST /api/sources/upload`.

### Git source

Для Git-ноды задайте HTTPS URL и необязательную ветку или тег. Репозиторий должен быть явно внесён в `ALLOWED_TARGETS` в корневом `.env`. Сопоставление выполняется по точному адресу owner/repository; URL с логином, паролем, query, fragment и нестандартным портом отклоняются.

Git clone выполняется shallow, без тегов, hooks, LFS smudge и submodules. Используется только HTTPS. Git устанавливается в backend image автоматически. Частные репозитории и credential helper пока не поддерживаются.

Пример:

```env
WORKSPACE_ROOT=/workspace
ALLOWED_TARGETS=https://github.com/example/training
```

## Текущий статус

Реализованы редактор React Flow с независимо сворачиваемыми боковыми панелями, реестр нод, валидация графа, сохранение workflow и версий, загрузка ZIP, allowlisted Git source, secrets scanner, начальный Gradle SCA-анализатор с локальным Maven advisory snapshot, Kotlin/Spring SAST (SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes, IDOR) с эталонным benchmark, устойчивая очередь PostgreSQL (`FOR UPDATE SKIP LOCKED`), отдельный worker с heartbeat и восстановлением просроченных задач.

Добавлена телеметрия последнего запуска: статус, время постановки в очередь/начала/завершения, длительность, общее число находок и распределение по severity, длительность каждого сканера и прогресс узлов. API предоставляет `/api/workflows/{workflow_id}/telemetry/latest`, `/api/runs/{run_id}/telemetry` и SSE-поток `/api/runs/{run_id}/events`. Интерфейс получает прогресс через SSE и использует polling как резервный режим.

Остаются в разработке: полноценный межпроцедурный AST/taint-анализ Kotlin SAST, Spring Boot dependency management и расширение транзитивного SCA. AI Explanation Gateway и объяснения по находкам реализованы как необязательная интеграция. GitHub Actions проверяет backend tests, frontend build и benchmark-наборы.

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

Security findings include a concise root-cause explanation (`why_it_matters`), a remediation recommendation, CWE/CVE identifiers where available, and a short source excerpt with the affected line highlighted. Source excerpts are path-confined to the scanned workspace and size-limited. For any SECRET finding, the entire surrounding source excerpt is hidden (including private-key material); for other categories, common credential assignments, bearer values, and known token formats are redacted before they are returned to the UI.

The source viewer endpoint is `GET /api/runs/{run_id}/findings/{fingerprint}/source?start_line=1&end_line=100`; it accepts only a finding persisted for the specified run. The API returns at most 300 lines per request.

The editor shows explicit workflow node states (ready, running, completed, blocked, failed, configuration required), explanations for blocked/configuration states, animated active edges, and an execution timeline from persisted worker events. Secrets, SCA, and SAST scanners report file-level progress (files scanned / total and current relative path); this is real scanner progress, not a simulated animation. Findings can be searched, filtered by severity, grouped by file, and navigated in sequence. The source viewer loads paginated windows from the original file, highlights the affected line, and enforces a run-scoped source boundary: the API resolves only the source artifact recorded in that run and only files inside that artifact. Symlinks, traversal paths, files larger than 1 MiB, and oversized line windows are rejected. Secret-category files are fully redacted in this viewer; common credential assignments and token patterns are redacted for other findings.


## AI Explanation Gateway

The optional `ai.explain` node calls an OpenAI-compatible `/chat/completions` endpoint.
Configure `LLM_BASE_URL`, `LLM_MODEL`, and `LLM_API_KEY` in the root `.env`
file (the worker reads the same environment). Remote endpoints must use HTTPS;
localhost is allowed for local development. No API key is stored in a workflow graph.

The gateway receives only an allowlisted subset of finding fields and redacted code
context; masked values, secret hashes, and raw secret fields are excluded. The model
may explain impact and remediation but cannot add findings, change severity, or
replace scanner decisions. Returned explanations are matched to known fingerprints,
validated, persisted with findings, and displayed separately from deterministic
scanner explanations. If the provider is not configured, the node reports
`configuration_required` and the workflow remains partial rather than silently
pretending that AI analysis ran.


### Workspace persistence

ZIP uploads and Git clones are stored in the named Docker volume mounted at
`/workspace` in both API and worker containers. This shared mount is
required: the API receives ZIP files, while the worker scans them later.
The Compose configuration pins `WORKSPACE_ROOT=/workspace` so the two
containers cannot accidentally use separate temporary directories.


### Project ZIP export

В окне Project Workspace доступны кнопки «Скачать ZIP» и «Скачать файл» для выбранного элемента. Отдельный файл ограничен 100 MiB; текстовые файлы — 1 MiB и проходят ту же проверку на секреты. Экспорт формируется на сервере во временный файл и удаляется после отправки. В архив не попадают `.git`, символьные ссылки, файлы из каталогов/путей с маркерами секретов, текстовые файлы с обнаруженными учётными данными и текстовые файлы больше 1 MiB (их содержимое не экспортируется без полной проверки). Отдельный предел готового ZIP — 1 GiB; отдельные файлы больше 512 MiB пропускаются. Файлы проекта не исполняются.

### Safe project asset preview

The project workspace previews PNG, JPEG, WebP, GIF and PDF files through `GET /api/projects/{project_id}/preview?path=...`. Preview is limited to 20 MiB per file. SVG, HTML and other active content are intentionally not rendered.
