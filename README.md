# AI Security Workflow

**Визуальная платформа автоматизации проверок безопасности кода**

Кейс Банка «Центр-инвест» · [CyberGarden 2026](https://cybergarden.ru)

Репозиторий: [github.com/VinfinityVois/INVEST](https://github.com/VinfinityVois/INVEST)

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

В левой панели доступна постоянная библиотека проектов. Добавление ZIP создаёт отдельную запись и каталог в `WORKSPACE_ROOT/projects`. Проект можно открыть прямо в площадке (дерево файлов + безопасный текстовый просмотр), искать текст по исходникам с переходом к совпавшей строке, редактировать поддерживаемые текстовые файлы, обновить новой версией ZIP, переименовать или удалить. Кнопка «Применить» подключает проект к блоку `Project source` текущего workflow одним нажатием, не открывая рабочую область. Кнопка «Открыть» отдельно показывает дерево файлов, просмотрщик и историю. При открытии путь проекта также устанавливается в блок `Project source`; граф получает имя проекта.

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

Git clone выполняется shallow, без тегов, hooks, LFS smudge и submodules. В `ref` можно указать ветку/тег либо полный 40-символьный commit SHA; SHA извлекается отдельно и checkout выполняется detached. Опциональный `subdirectory` ограничивает сканирование вложенной папкой checkout (абсолютные пути, `..` и symlinks запрещены). Используется только HTTPS. Git устанавливается в backend image автоматически. Частные репозитории и credential helper пока не поддерживаются.

Пример:

```env
WORKSPACE_ROOT=/workspace
ALLOWED_TARGETS=https://github.com/example/training
```


## Демонстрационный сценарий: учебный Kotlin-проект

Для воспроизводимого показа используйте публичный учебный репозиторий [TBagirov/training](https://github.com/TBagirov/training), зафиксированный CI на commit \`fe1fcbe212669783480666b9b60147c8a8c6eef4\`. Это специально подготовленный учебный стенд, а не production-цель. Добавьте точный URL в корневой \`.env\`:

\`\`\`env
ALLOWED_TARGETS=https://github.com/TBagirov/training
NOTIFY_WEBHOOK_ALLOWED_HOSTS=webhook.site
\`\`\`

Путь демонстрационного Kotlin/Spring-проекта внутри репозитория: \`training-project/\`. Создайте workflow с цепочкой:

\`Manual trigger → Git repository → Secrets scanner / Dependency scanner / Kotlin SAST → Merge findings → AI explanation → Webhook\`

Для Git source задайте URL репозитория и ref \`fe1fcbe212669783480666b9b60147c8a8c6eef4\`. Репозиторий сканируется как данные; Gradle и приложение не запускаются. В репозитории также есть ground-truth и benchmark-файлы — для формальной оценки используйте команды из \`eval/README.md\`, которые направляют сканеры непосредственно на \`training-project/\`.

После добавления workflow сохраните его, создайте уникальный endpoint на [webhook.site](https://webhook.site/), укажите полный HTTPS URL в настройках Webhook-ноды и нажмите «Запустить всё». В webhook.site должен прийти JSON с количеством находок, распределением severity, первыми десятью находками и краткими AI-объяснениями. Содержимое исходного кода, code context, masked values и ключи API в уведомление не включаются.

Для автоматического запуска этого сценария из PowerShell используйте готовый скрипт (он создаёт workflow через API, ставит run в очередь, опрашивает его статус и выводит execution trace):

\`\`\`powershell
.\scripts\demo.ps1 -WebhookUrl "https://webhook.site/ВАШ-УНИКАЛЬНЫЙ-ID"
\`\`\`

Перед запуском задайте в корневом \`.env\`:
\`\`\`env
ALLOWED_TARGETS=https://github.com/TBagirov/training
NOTIFY_WEBHOOK_ALLOWED_HOSTS=webhook.site
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=ВАША_OPENAI_COMPATIBLE_MODEL
LLM_API_KEY=ВАШ_API_KEY
\`\`\`
После изменения \`.env\` перезапустите API и worker. Для провайдера, отличного от OpenAI, укажите его OpenAI-compatible endpoint и модель.


## Расписание workflow

Для запуска по времени добавьте на холст блок **Schedule trigger** вместо Manual trigger. В конфигурации задайте пяти-польное cron-выражение и IANA timezone, например:

\`\`\`text
Cron: */5 * * * *
Timezone: Europe/Amsterdam
\`\`\`

Выберите «Сохранить и включить расписание» в инспекторе ноды. Состояние расписания, следующий и последний запуск отображаются там же. Отключение расписания не удаляет workflow и историю запусков.

Worker проверяет расписания каждые 2 секунды, атомарно блокирует наступившие записи через PostgreSQL FOR UPDATE SKIP LOCKED и создаёт обычные задания в существующей очереди. Несколько worker-процессов не должны поставить один и тот же интервал в очередь. После простоя пропущенные интервалы не воспроизводятся пачкой: ставится один запуск, а следующее время вычисляется от текущего момента. Время хранится в UTC, cron вычисляется в выбранной timezone.

API:
- GET /api/workflows/{id}/schedule — состояние расписания;
- PUT /api/workflows/{id}/schedule с JSON {"enabled": true} — включить по конфигурации Schedule trigger;
- PUT /api/workflows/{id}/schedule с JSON {"enabled": false} — отключить.

### Настройка Webhook

- В \`.env\` задаётся \`NOTIFY_WEBHOOK_ALLOWED_HOSTS\` — точный список разрешённых DNS-hostname через запятую; по умолчанию разрешён только \`webhook.site\`.
- Нода принимает только HTTPS на порту 443, без credentials, query и fragment.
- DNS-адреса проверяются на публичную маршрутизируемость; redirects запрещены, proxy из окружения не используется.
- Таймаут доставки — 10 секунд. Ошибка доставки помечает ноду и запуск как failed; незаданный URL отображается как configuration required.
- В payload попадают только ограниченные поля находок и AI summary. Секретоподобные значения и фрагменты исходников не передаются.


## Текущий статус

Реализованы редактор React Flow с независимо сворачиваемыми боковыми панелями, реестр нод, валидация графа, сохранение workflow и версий, загрузка ZIP, allowlisted Git source, secrets scanner, Gradle и Maven SCA-анализаторы с локальным Maven advisory snapshot, Kotlin/Spring SAST (SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes, IDOR) с эталонным benchmark, устойчивая очередь PostgreSQL (`FOR UPDATE SKIP LOCKED`), отдельный worker с heartbeat и восстановлением просроченных задач.

Сравнение запусков сохраняет ограниченный неизменяемый снимок исходников (относительный путь, размер и SHA-256 без содержимого файлов). В сравнении показываются добавленные, изменённые и удалённые файлы; новые/сохраняющиеся/исчезнувшие находки получают осторожную привязку к пути файла. Совпадение пути — только корреляция, не доказательство причинности. Для старых запусков, неполных снимков и источников за пределами лимитов состояние остаётся неизвестным.

Добавлена телеметрия последнего запуска: статус, время постановки в очередь/начала/завершения, длительность, общее число находок и распределение по severity, длительность каждого сканера и прогресс узлов. API предоставляет `/api/workflows/{workflow_id}/telemetry/latest`, `/api/runs/{run_id}/telemetry` и SSE-поток `/api/runs/{run_id}/events`. Интерфейс получает прогресс через SSE и использует polling как резервный режим.

Kotlin SAST дополнен ограниченным межпроцедурным taint-анализом в пределах одного проекта: отслеживаются HTTP-параметры с аннотациями RequestParam/PathVariable/RequestBody/RequestHeader/CookieValue и request.getParameter/getHeader/getQueryString через локальные присваивания и прямые вызовы функций, в том числе между разными `.kt` файлами, до SQL API. Находка указывает на файл и строку SQL sink, а не на точное место возникновения taint. Параметризованные SQL-запросы с bind-параметрами не отмечаются этим правилом. Анализ ограничен фиксированным числом итераций и остаётся лексическим: разрешение перегрузок, receiver/type resolution, полноценный Kotlin AST/PSI, межмодульный call graph и полноценный анализ ветвлений/потоков управления ещё не реализованы. Для SQL taint учитываются только узкие преобразования в числовые типы и UUID; HTML/URL escaping намеренно не считается SQL sanitizer, поскольку очистка должна соответствовать контексту sink. Репозиторный код не компилируется и не исполняется. Gradle SCA читает стандартный и явно объявленные custom catalogs `*.versions.toml`; распознаёт aliases в вызовах Gradle dependency configurations (включая нестандартные вроде `kapt(...)`) и `add("configuration", catalog.alias)`. Поддерживает `module` либо `group`/`name`, строковые версии, `version.ref` и `[bundles]` (bundle раскрывается только если все его library aliases известны). Из rich version constraints без lockfile используется только точная числовая версия `strictly`; `require`, `prefer` и version ranges не считаются фактически разрешённой версией. Если доступен `gradle.lockfile` рядом с build-файлом, зафиксированная версия имеет приоритет над объявленной. TOML читается статически через стандартную библиотеку Python; Gradle не запускается. Неизвестные aliases, отсутствующие версии и некорректный TOML пропускаются без догадок. Spring Boot BOM поддерживается статически для явных импортов `platform(...)`, `enforcedPlatform(...)` и `mavenBom(...)`. Локальный `data/spring-boot-managed-versions.json` содержит версионированный, курируемый поднабор координат для Spring Boot BOM `3.2.0`, `3.3.0`, `3.4.0` и `3.5.0`, сверенный с исходным dependency catalog и `gradle.properties` соответствующих тегов. Версия из lockfile имеет приоритет, затем явная версия зависимости, затем версия из BOM. Неизвестная версия BOM, отсутствующая координата и конфликтующие версии нескольких импортированных BOM не разрешаются догадками. Снимок не является полным BOM; покрытие расширяется отдельно. При наличии `gradle.lockfile` scanner дополнительно проверяет все зафиксированные координаты, включая транзитивные зависимости, даже если они отсутствуют в `build.gradle`; путь и строка находки указывают на lockfile. Прямые зависимости не дублируются второй находкой из lockfile. Для переопределения версии прямой зависимости используется lockfile только когда для координаты существует одна однозначная версия; если разные конфигурации фиксируют разные версии, scanner не выбирает одну произвольно. Без lockfile транзитивные resolved versions не выводятся из одних деклараций, полноценный граф зависимостей и разрешение Gradle variant/capability ещё не реализованы. Maven SCA статически читает `pom.xml`: обрабатывает прямые dependencies, `dependencyManagement`, простые `${property}` ссылки, локальные parent properties и `dependencyManagement` с наследованием по цепочке локальных parent POM (с ограничением глубины и путей), активные `activeByDefault` profiles, профили из `-P` и профили с активацией по `-D` user properties в корневом `.mvn/maven.config` (настройка применяется к reactor-модулям). При импорте Spring Boot `spring-boot-dependencies` применяет тот же ограниченный snapshot версий `3.2.0`–`3.5.0`; неизвестные BOM и неразрешённые версии не угадываются. Для транзитивных Maven-зависимостей можно положить текстовый отчёт Maven Dependency Plugin в файл с именем `*dependency-tree*.txt`; scanner разбирает координаты с типом, версией и scope и указывает точную строку отчёта. Профили, активируемые окружением, JDK, системными свойствами или внешним `settings.xml`, не вычисляются; удалённые BOM и полноценный Maven dependency graph не разрешаются. Maven/Gradle и код проекта не запускаются. AI Explanation Gateway и объяснения по находкам реализованы как необязательная интеграция. GitHub Actions проверяет backend tests, frontend build и benchmark-наборы.

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

The optional `ai.explain` node calls an OpenAI-compatible `/chat/completions` endpoint. The UI reads `GET /api/ai/status` to show whether the three settings are present; this endpoint never returns the API key. Provider failures distinguish authentication (401/403), missing endpoint/model (404), quota/rate limit (429), connection failures and timeouts. If a compatible server rejects `response_format`, the gateway retries once without that optional parameter.
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
