# AI Security Workflow

**Визуальная платформа автоматизации проверок безопасности кода**

Кейс Банка «Центр-инвест» · [CyberGarden 2026](https://cybergarden.ru)

Репозиторий: [github.com/VinfinityVois/INVEST](https://github.com/VinfinityVois/INVEST)

## Публичный доступ

**Временная ссылка на веб-интерфейс:** https://conditional-carlo-kitchen-globe.trycloudflare.com
тест-логин  sever_vv304ubk@mail.ru
тест-пароль  1234567890ART!@

Ссылка создана через Cloudflare Quick Tunnel и доступна, пока локальный frontend INVEST и процесс `cloudflared` запущены на компьютере разработчика. После остановки туннеля или его повторного запуска адрес может перестать работать или измениться. Это временный демонстрационный адрес, не постоянный production-домен.

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

## Первый вход

После первого запуска и применения миграций создай единственную первоначальную учётную запись администратора. Команда интерактивно запросит пароль (не передавай пароль аргументом командной строки):

```powershell
docker compose exec api python -m app.bootstrap_admin admin@example.test
```

Bootstrap разрешён только пока в базе нет администратора. Повторный запуск не меняет существующие учётные записи. Для аккаунта создаются личные Organization и Workspace; первый bootstrap-администратор также получает доступ к legacy workspace, куда миграция переносит прежние проекты. Вход выполняется через UI; API использует серверную HttpOnly-сессию и активный Workspace в серверной сессии. Проекты, workflows, runs, findings и отчёты в browser API ограничиваются активным Workspace. Это первый tenant-isolation слой, а не заявление о полном production RBAC: CI токены теперь workspace-scoped, но invitations/email, полный аудит, экспорт/удаление workspace, backup/restore и системная security-проверка ещё остаются в backlog.

## Dashboard / Analytics

Кнопка «Обзор» открывает workspace-scoped dashboard: projects, workflows, scans, findings и severity counts; динамика запусков/findings; последние runs со ссылками на HTML/JSON отчёты. Фильтры: период 7/30/90 дней, проект, severity и scanner. API: `GET /api/dashboard/summary`; все агрегаты ограничены активным Workspace. При выборе проекта workflow должен быть связан с ним через source.upload path; если граф использует ровно один project source, связь сохраняется в `workflows.project_id`.

## Organizations и Workspace

Модель данных: `User → Organization → Workspace → Project`. У каждого пользователя есть личная Organization и default Workspace. Командные организации могут иметь несколько Workspace. Системные роли организации: Owner, Admin, Member; роли Workspace: Admin, Editor, Analyst, Viewer. Активная рабочая область хранится в серверной сессии, а не принимается из произвольного client header.

В UI через кнопку «Доступы» доступны создание организации и Workspace, добавление уже существующих аккаунтов, просмотр участников, управление workspace roles, отзыв членства и передача владения организацией. Приглашения по email и самостоятельная регистрация по приглашению пока не реализованы. Старые проекты/workflows мигрируются в legacy Workspace первого администратора; остальные старые аккаунты получают собственные пустые personal workspaces.

API:
- `GET /api/organizations`, `POST /api/organizations`;
- `GET /api/workspaces`, `GET /api/workspaces/active`, `POST /api/workspaces`, `PATCH /api/workspaces/{id}`, `POST /api/workspaces/{id}/switch`;
- `GET /api/organizations/{id}/members`, `POST /api/organizations/{id}/members`, `DELETE /api/organizations/{id}/members/{user_id}`, `POST /api/organizations/{id}/transfer-ownership`;
- `GET /api/workspaces/{id}/members`, `POST /api/workspaces/{id}/members`, `PATCH /api/workspaces/{id}/members/{user_id}`, `DELETE /api/workspaces/{id}/members/{user_id}`.

API tokens создаются отдельно для Workspace. Поддерживаемые scopes: `workflow:run`, `run:read`, `template:publish`. Полный секрет показывается только при создании; БД хранит только SHA-256 hash. Если срок не задан, токен истекает через 90 дней; отозванные токены не восстанавливаются. CI endpoints проверяют scope и совпадение Workspace токена с Workspace workflow/run. Старые глобальные `CI_TRIGGER_TOKEN` и `TEMPLATE_PUBLISH_TOKEN` больше не используются.

## Локальный запуск без Docker (Windows PowerShell)

Если backend запускается напрямую через Uvicorn, установи зависимости именно в тот Python, которым запускается сервер. В частности, планировщик использует `croniter`, уже включённый в `backend/requirements.txt`:

```powershell
cd C:\\MYDESK\\HAK\\INVEST\\backend
py -3.14 -m pip install -r requirements.txt
py -3.14 -m alembic upgrade head
py -3.14 -m uvicorn app.main:app --reload --port 8000
```

Во втором окне PowerShell, из той же папки и с тем же Python, обязательно запусти worker:

```powershell
py -3.14 -m app.worker
```

Uvicorn принимает и ставит задания в очередь, но не выполняет их сам. Без отдельного worker кнопка «Запустить всё» сможет поставить запуск в очередь, однако блоки не начнут исполняться. Для полного окружения с API, PostgreSQL, worker и frontend используй `docker compose up --build` из корня репозитория.

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

`POST /api/sources/upload` также создаёт запись проекта в активном Workspace; анонимных или бесхозных загрузок нет.

### Git source

Для Git-ноды задайте HTTPS URL и необязательную ветку или тег. Сначала добавьте репозиторий в **Главное меню → Интеграции платформы** активной рабочей области. Разрешения хранятся в БД отдельно для каждого Workspace; URL с логином, паролем, query, fragment и нестандартным портом отклоняются. `ALLOWED_TARGETS` остаётся только для обратной совместимости со старыми рабочими областями, в которых ещё не задан список репозиториев.

Git clone выполняется shallow, без тегов, hooks, LFS smudge и submodules. В `ref` можно указать ветку/тег либо полный 40-символьный commit SHA; SHA извлекается отдельно и checkout выполняется detached. Опциональный `subdirectory` ограничивает сканирование вложенной папкой checkout (абсолютные пути, `..` и symlinks запрещены). Используется только HTTPS. Git устанавливается в backend image автоматически. Частные репозитории и credential helper пока не поддерживаются.

Пример:

```env
WORKSPACE_ROOT=/workspace
```


## AI-генерация workflow

В редакторе доступна кнопка `AI-граф`. Она отправляет описание задачи в настроенный OpenAI-compatible LLM и возвращает только черновик графа через `POST /api/workflows/generate`.

Генератор использует реестр блоков и их типизированные порты как allowlist. Сервер повторно проверяет типы узлов, поля конфигурации, связи, циклы и достижимость всех блоков от единственного триггера. ID и координаты назначаются сервером. Ограничения: 2–30 блоков, до 60 связей, обязательны источник и хотя бы один scanner. URL Git, webhook destination и локальный путь не генерируются — они остаются пустыми для ручной настройки.

Граф только помещается на холст как черновик. Он не сохраняется и не запускается автоматически; перед использованием нажми «Проверить», затем «Сохранить». AI не добавляет findings и не влияет на решения сканеров. Текст запроса проходит базовую маскировку известных форматов секретов перед отправкой провайдеру. Не включай в запрос конфиденциальный исходный код, токены или приватные данные.

## Каталог workflow

Встроенный каталог содержит готовые конструкции, которые клонируются в активный Workspace как новые workflow и не запускаются автоматически:

- **PR Gate** — полный Secrets + SCA + Kotlin/Spring SAST + CI Gate;
- **Экспресс-проверка секретов** — быстрый secrets scan и policy gate;
- **Аудит зависимостей** — Maven/Gradle SCA, AI-объяснения и gate;
- **Аудит Kotlin / Spring** — SAST, AI-рекомендации и gate;
- **Полный AppSec Gate** — три сканера, Merge, AI и Security Gate;
- **AI-триаж критичных находок** — logic.compare отбирает HIGH/CRITICAL для AI, gate получает полный набор;
- **Плановый полный аудит** — Schedule trigger с будничным расписанием, три сканера, AI и gate.

У встроенных решений источник проекта оставлен незаполненным: после клонирования выберите проект из библиотеки или настройте разрешённый Git-источник. Для AI-блоков нужны LLM-настройки. Каталог также показывает собственные сохранённые workflow активного Workspace, чтобы их можно было открыть после перезагрузки страницы.

Редактор автоматически сохраняет изменения workflow с небольшой задержкой после редактирования. Последний открытый workflow восстанавливается из Workspace после обновления страницы; незавершённый черновик дополнительно резервируется в localStorage этого браузера без секретных полей и адресов уведомлений. При ошибке API черновик остаётся локально и виден статус автосохранения. Последний запуск активного workflow также восстанавливает findings и telemetry после обновления страницы. Ручная кнопка «Сохранить» и сохранение перед запуском остаются доступны.

## Библиотека шаблонов workflow

Публичная библиотека содержит только опубликованные графы, очищенные от конфигурационных секретов. Просмотр и клонирование не запускают workflow. При клонировании генерируются новые ID узлов и рёбер, а затем граф повторно проходит серверную валидацию.

Публикация требует workspace-scoped API token с разрешением `template:publish`. Создайте его в меню «Доступы» для нужного Workspace; секрет показывается один раз, хранится в БД только в виде SHA-256 hash и передаётся в заголовке `X-Template-Publish-Token`. Не помещайте токен во frontend или в граф workflow.

API:
- `GET /api/templates` — список опубликованных шаблонов (фильтры `category` и `q`);
- `GET /api/templates/{id}` — очищенный граф шаблона;
- `POST /api/templates/publish` — публикация сохранённого workflow; требует workspace token scope `template:publish` в `X-Template-Publish-Token`;
- `POST /api/templates/{id}/clone` — создание нового сохранённого workflow без выполнения.

При публикации рекурсивно удаляются поля с именами, похожими на секреты/учётные данные, локальные пути `source.upload` и URL назначения `notify.webhook`. Git URL очищается от user-info, query и fragment. В webhook-ноду записывается безопасный placeholder `example.invalid`, который необходимо заменить перед использованием. Сама публикация не ставит задания в очередь. Публикация ограничена Workspace, к которому привязан токен; токен нельзя использовать для чтения или запуска workflow без соответствующих scopes.

## Logic.compare — фильтрация находок

Нода `logic.compare` разделяет findings на выходы `true` и `false`. Поддерживаются поля severity, rule_id, path, category, message, cve, cwe и count; операторы equals/not_equals, contains/not_contains, greater_than/greater_or_equal/less_than/less_or_equal. Для severity числовое сравнение использует порядок CRITICAL > HIGH > MEDIUM > LOW > INFO. Выходы можно подключать независимо к следующим нодам.

## Демонстрационный сценарий: учебный Kotlin-проект

Краткий сценарий презентации, preflight и проверка полного прогона: [docs/demo-runbook.md](docs/demo-runbook.md).

Для воспроизводимого показа используйте публичный учебный репозиторий [TBagirov/training](https://github.com/TBagirov/training), зафиксированный CI на commit \`fe1fcbe212669783480666b9b60147c8a8c6eef4\`. Это специально подготовленный учебный стенд, а не production-цель. Добавьте `https://github.com/TBagirov/training` в список Git-репозиториев и `webhook.site` в список webhook-доменов через **Главное меню → Интеграции платформы** активной рабочей области.

Путь демонстрационного Kotlin/Spring-проекта внутри репозитория: \`training-project/\`. Создайте workflow с цепочкой:

\`Manual trigger → Git repository → Secrets scanner / Dependency scanner / Kotlin SAST → Merge findings → AI explanation → Webhook\`

Для Git source задайте URL репозитория и ref \`fe1fcbe212669783480666b9b60147c8a8c6eef4\`. Репозиторий сканируется как данные; Gradle и приложение не запускаются. В репозитории также есть ground-truth и benchmark-файлы — для формальной оценки используйте команды из \`eval/README.md\`, которые направляют сканеры непосредственно на \`training-project/\`.

В примере также подключён `CI security gate` напрямую к `Merge findings`: он оценивает все результаты сканеров независимо от AI-объяснений и уведомления. После добавления workflow сохраните его, создайте уникальный endpoint на [webhook.site](https://webhook.site/), укажите полный HTTPS URL в настройках Webhook-ноды и нажмите «Запустить всё». В webhook.site должен прийти JSON с количеством находок, распределением severity, первыми десятью находками и краткими AI-объяснениями. Содержимое исходного кода, code context, masked values и ключи API в уведомление не включаются.

Для автоматического запуска этого сценария из PowerShell используйте готовый скрипт (он создаёт workflow через API, ставит run в очередь, опрашивает его статус и выводит execution trace):

\`\`\`powershell
.\scripts\demo.ps1 -WebhookUrl "https://webhook.site/ВАШ-УНИКАЛЬНЫЙ-ID"
\`\`\`

Перед запуском добавьте репозиторий и hostname webhook через **Главное меню → Интеграции платформы**. В корневом `.env` остаются только инфраструктурные параметры и настройки LLM:
```env
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=ВАША_OPENAI_COMPATIBLE_MODEL
LLM_API_KEY=ВАШ_API_KEY
```
Для провайдера, отличного от OpenAI, укажите его OpenAI-compatible endpoint и модель.


## Условная фильтрация находок

Нода **Compare findings** разделяет входящий список на два потока по полю: severity, rule_id, path, category, message, cve, cwe или count; и оператору: equals, not_equals, contains, not_contains, greater_than, greater_or_equal, less_than, less_or_equal. Подключайте рёбра от выходов true и false: downstream-блоки получат только соответствующую часть findings. Для числовых операторов поле должно содержать число; count сравнивает общее количество входящих находок. Нода не изменяет исходные finding и не меняет их severity.

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

### Интеграции платформы

Откройте **Главное меню → Интеграции платформы** в интерфейсе INVEST. Настройки сохраняются в активной рабочей области:

- **Git** — список HTTPS-репозиториев, которым разрешено запускаться в Git source.
- **Telegram** — токен бота и chat IDs по умолчанию. Токен шифруется AES-256-GCM и никогда не возвращается браузеру.
- **Webhook** — список разрешённых DNS-hostname. Нода по-прежнему задаёт конкретный HTTPS URL, а сервер проверяет hostname, DNS и публичность IP.
- Доступ к изменению настроек имеют только администраторы Workspace; каждое изменение попадает в audit log.
- Если мастер-ключ не задан вручную, Docker создаёт его автоматически в отдельном persistent volume, общем для API и worker. Не удаляйте этот volume: без него сохранённые секреты нельзя расшифровать.

Legacy-переменные `ALLOWED_TARGETS`, `TELEGRAM_ALLOWED_CHAT_IDS`, `TELEGRAM_BOT_TOKEN` и `NOTIFY_WEBHOOK_ALLOWED_HOSTS` поддерживаются как fallback для старых конфигураций. Для новых настроек используйте интерфейс.

### Настройка Webhook

- Разрешённые DNS-hostname настраиваются в **Главное меню → Интеграции платформы** и сохраняются отдельно для каждого Workspace. `NOTIFY_WEBHOOK_ALLOWED_HOSTS` остаётся legacy-резервом, если в Workspace ещё нет настроек.
- Нода принимает только HTTPS на порту 443, без credentials, query и fragment.
- DNS-адреса проверяются на публичную маршрутизируемость; redirects запрещены, proxy из окружения не используется.
- Таймаут доставки — 10 секунд. Ошибка доставки помечает ноду и запуск как failed; незаданный URL отображается как configuration required.
- В payload попадают только ограниченные поля находок и AI summary. Секретоподобные значения и фрагменты исходников не передаются.


## Текущий статус

Реализованы редактор React Flow с независимо сворачиваемыми боковыми панелями, реестр нод, валидация графа, сохранение workflow и версий, загрузка ZIP, allowlisted Git source, secrets scanner, Gradle и Maven SCA-анализаторы с локальным Maven advisory snapshot, Kotlin/Spring SAST (SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes, IDOR) с эталонным benchmark, устойчивая очередь PostgreSQL (`FOR UPDATE SKIP LOCKED`), отдельный worker с heartbeat и восстановлением просроченных задач.

Сравнение запусков сохраняет ограниченный неизменяемый снимок исходников (относительный путь, размер и SHA-256 без содержимого файлов). В сравнении показываются добавленные, изменённые и удалённые файлы; новые/сохраняющиеся/исчезнувшие находки получают осторожную привязку к пути файла. Совпадение пути — только корреляция, не доказательство причинности. Для старых запусков, неполных снимков и источников за пределами лимитов состояние остаётся неизвестным.

Добавлена телеметрия последнего запуска: статус, время постановки в очередь/начала/завершения, длительность, общее число находок и распределение по severity, длительность каждого сканера и прогресс узлов. API предоставляет `/api/workflows/{workflow_id}/telemetry/latest`, `/api/runs/{run_id}/telemetry` и SSE-поток `/api/runs/{run_id}/events`. Интерфейс получает прогресс через SSE и использует polling как резервный режим.

Kotlin SAST дополнен ограниченным межпроцедурным taint-анализом в пределах одного проекта: отслеживаются HTTP-параметры с аннотациями RequestParam/PathVariable/RequestBody/RequestHeader/CookieValue и request.getParameter/getHeader/getQueryString через локальные присваивания и прямые вызовы функций, в том числе между разными `.kt` файлами, до SQL API. Находка указывает на файл и строку SQL sink, а не на точное место возникновения taint. Параметризованные SQL-запросы с bind-параметрами не отмечаются этим правилом. Анализ ограничен фиксированным числом итераций и остаётся лексическим: разрешение перегрузок, receiver/type resolution, полноценный Kotlin AST/PSI, межмодульный call graph и полноценный анализ ветвлений/потоков управления ещё не реализованы. Для SQL taint учитываются только узкие преобразования в числовые типы и UUID; HTML/URL escaping намеренно не считается SQL sanitizer, поскольку очистка должна соответствовать контексту sink. Репозиторный код не компилируется и не исполняется. Gradle SCA читает стандартный и явно объявленные custom catalogs `*.versions.toml`; распознаёт aliases в вызовах Gradle dependency configurations (включая нестандартные вроде `kapt(...)`) и `add("configuration", catalog.alias)`. Поддерживает `module` либо `group`/`name`, строковые версии, `version.ref` и `[bundles]` (bundle раскрывается только если все его library aliases известны). Из rich version constraints без lockfile используется только точная числовая версия `strictly`; `require`, `prefer` и version ranges не считаются фактически разрешённой версией. Если доступен `gradle.lockfile` рядом с build-файлом, зафиксированная версия имеет приоритет над объявленной. TOML читается статически через стандартную библиотеку Python; Gradle не запускается. Неизвестные aliases, отсутствующие версии и некорректный TOML пропускаются без догадок. Spring Boot BOM поддерживается статически для явных импортов `platform(...)`, `enforcedPlatform(...)` и `mavenBom(...)`. Локальный `data/spring-boot-managed-versions.json` содержит версионированный, курируемый поднабор координат для Spring Boot BOM `3.2.0`, `3.3.0`, `3.4.0` и `3.5.0`, сверенный с исходным dependency catalog и `gradle.properties` соответствующих тегов. Версия из lockfile имеет приоритет, затем явная версия зависимости, затем версия из BOM. Неизвестная версия BOM, отсутствующая координата и конфликтующие версии нескольких импортированных BOM не разрешаются догадками. Снимок не является полным BOM; покрытие расширяется отдельно. При наличии `gradle.lockfile` scanner дополнительно проверяет все зафиксированные координаты, включая транзитивные зависимости, даже если они отсутствуют в `build.gradle`; путь и строка находки указывают на lockfile. Прямые зависимости не дублируются второй находкой из lockfile. Для переопределения версии прямой зависимости используется lockfile только когда для координаты существует одна однозначная версия; если разные конфигурации фиксируют разные версии, scanner не выбирает одну произвольно. Без lockfile транзитивные resolved versions не выводятся из одних деклараций, полноценный граф зависимостей и разрешение Gradle variant/capability ещё не реализованы. Maven SCA статически читает `pom.xml`: обрабатывает прямые dependencies, `dependencyManagement`, простые `${property}` ссылки, локальные parent properties и `dependencyManagement` с наследованием по цепочке локальных parent POM (с ограничением глубины и путей), активные `activeByDefault` profiles, профили из `-P` и профили с активацией по `-D` user properties в корневом `.mvn/maven.config` (настройка применяется к reactor-модулям). При импорте Spring Boot `spring-boot-dependencies` применяет тот же ограниченный snapshot версий `3.2.0`–`3.5.0`; неизвестные BOM и неразрешённые версии не угадываются. Для транзитивных Maven-зависимостей можно положить текстовый отчёт Maven Dependency Plugin в файл с именем `*dependency-tree*.txt`; scanner разбирает координаты с типом, версией и scope и указывает точную строку отчёта. Профили, активируемые окружением, JDK, системными свойствами или внешним `settings.xml`, не вычисляются; удалённые BOM и полноценный Maven dependency graph не разрешаются. Maven/Gradle и код проекта не запускаются. AI Explanation Gateway и объяснения по находкам реализованы как необязательная интеграция. GitHub Actions проверяет backend tests, frontend build и benchmark-наборы.

## Secrets scanner: entropy and context

Secrets detection is implemented by the in-house scanner. In addition to provider-specific patterns, named assignments and bearer configuration, it now checks Shannon entropy for quoted literals assigned to secret-related names (password, secret, token, API key, credential, authorization). The entropy rule is deliberately bounded: values must be at least 20 characters and have entropy of at least 3.5 bits per character. It does not scan arbitrary random strings in unrelated variables, and it avoids adding a second finding when another secret rule already matched the same line. Detected values are masked and hashed before findings are returned.

The entropy threshold is a confidence signal, not proof that a value is live. The scanner still does not inspect Git history; repository files are analyzed as a bounded working-tree snapshot.

## Принципы безопасности

- Репозитории рассматриваются как недоверенные данные: никакого запуска Gradle, Maven или скриптов проекта.
- Никаких готовых security-сканеров; детекция реализуется собственными правилами.
- LLM не определяет уязвимости и не придумывает CVE — только объясняет уже найденные проблемы.
- Секреты не должны попадать в логи, API-ответы или AI-контекст в открытом виде.
- Git scanning разрешён только для точных URL из allowlist.
- ZIP/Git checkout выполняется в workspace; запуск проектных файлов запрещён.


## GitHub Actions: запуск Security Gate

В \`.github/workflows/security-check.yml\` добавлен ручной CI workflow. Он вызывает сохранённый workflow в INVEST, ждёт завершения worker и возвращает ненулевой exit code при \`BLOCK\`, ошибке, частичном выполнении, отсутствии решения gate или timeout. \`PASS\` и \`WARN\` завершаются успешно.

### Настройка API

1. В UI откройте «Доступы», выберите Workspace, в блоке «API Tokens / CI» создайте токен со scopes \`workflow:run\` и \`run:read\`. При необходимости задайте срок действия.
2. Скопируйте секрет сразу после создания: он показывается один раз, в базе хранится только SHA-256 hash. Токен привязан к выбранному Workspace.
3. В настройках GitHub repository → Settings → Secrets and variables → Actions добавьте:
   - \`INVEST_API_BASE_URL\` — публичный HTTPS URL API, доступный GitHub-hosted runner;
   - \`INVEST_CI_TOKEN\` — созданный workspace-scoped API token.
4. В интерфейсе INVEST сохраните workflow в том же Workspace, содержащий ровно одну ноду \`CI security gate\`. Git-источник должен быть добавлен в Интеграции платформы активного Workspace.
5. Скопируйте UUID workflow и запустите GitHub Actions → **INVEST security check** → Run workflow, передав UUID.

CI API:
- \`POST /api/ci/workflows/{workflow_id}/runs\` — защищённый запуск сохранённого workflow; требует \`X-CI-Token\` и ровно одну Security Gate ноду;
- \`GET /api/ci/runs/{run_id}\` — защищённый минимальный polling endpoint; возвращает статус и решение gate без исходных findings или source excerpts.

Неизвестный, отозванный или истёкший токен получает \`401\`; токен без нужного scope — \`403\`. Токен другой рабочей области не может запускать workflow или читать run. Секрет передаётся только в заголовке; в БД хранится только hash. Не публикуйте API без HTTPS и сетевого ограничения доступа. GitHub-hosted runner не может обращаться к \`localhost\`; API должен быть доступен из runner либо используйте self-hosted runner в доверенной сети.

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


## Built-in SCA rule packs

The dependency scanner exposes repository-owned SCA packs through `GET /api/rule-packs?analyzer=sca`:

- `sca-maven-core` — Maven and Gradle dependency checks against the pinned local `data/maven-advisories.json` snapshot.
- `sca-spring-boot` — extends the core pack and adds the curated Spring Boot starter catalog from `data/spring-boot-starters.json`. Starter metadata classifies a dependency; it does not create vulnerability findings.

The `scan.sca` node configuration is schema-driven:

- `rule_packs` selects one or more compatible built-in packs;
- `advisory_db` accepts only the repository-owned `maven-advisories` database identifier (no arbitrary path or URL);
- `starter_pack` selects the optional Spring Boot starter catalog;
- `include_dev` controls Maven test/provided/system scopes and Gradle test configurations;
- `use_lockfile` controls Gradle lockfile version resolution and transitive lockfile entries.

Pack metadata and inheritance are validated at API startup. Pack content is treated as data: no rule file, build script, Maven or Gradle task is executed. SCA findings retain their ecosystem identifier, and Spring Boot starter classification is attached only to an advisory finding for a matching starter coordinate.


## Built-in workflow presets

The repository ships a versioned preset catalog in `presets/manifest.json`. The first built-in entry is `pr-gate`:

- manual trigger → allowlisted Git source;
- in-house Secrets scanner, SCA (Maven/Gradle) and Kotlin/Spring SAST;
- merged findings → exactly one deterministic CI Security Gate using `bank-strict`.

API:
- `GET /api/presets` lists built-in presets;
- `GET /api/presets/{preset_id}` returns a sanitized graph preview;
- `POST /api/presets/{preset_id}/clone` creates a new saved workflow with fresh node/edge IDs and does not execute it.

In the editor, open **Каталог workflow** → **Создать workflow** on **PR Gate**. Then replace the example Git URL with a repository URL already added in **Platform integrations** for the active Workspace, save the workflow, and run it. The resulting graph contains exactly one `ci.gate` node and can be used with the protected `/api/ci/workflows/{workflow_id}/runs` endpoint after a workspace API token with `workflow:run` and `run:read` scopes is created. Cloning never starts a scan automatically.
