# AI Security Workflow

Визуальная платформа для построения и запуска security-workflow: собственные анализаторы, AI-объяснения подтверждённых находок и уведомления.

## Архитектура

- **backend** — FastAPI, Pydantic, SQLAlchemy 2, PostgreSQL.
- **worker** — отдельный процесс исполнения графов (постоянная очередь ещё в разработке).
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

Реализованы редактор React Flow, реестр нод, валидация графа, синхронный executor, сохранение workflow и версий, загрузка ZIP, allowlisted Git source, secrets scanner, начальный Gradle SCA-анализатор с локальным Maven advisory snapshot, Kotlin/Spring SAST (SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes, IDOR) с эталонным benchmark, сохранение запусков и findings API/UI. Расширение Kotlin SAST до полноценного межпроцедурного AST/taint-анализа, Spring Boot dependency management, расширение транзитивного SCA, постоянная очередь worker, SSE, AI gateway и объяснения остаются в разработке. GitHub Actions проверяет backend tests и frontend build.

## Принципы безопасности

- Репозитории рассматриваются как недоверенные данные: никакого запуска Gradle, Maven или скриптов проекта.
- Никаких готовых security-сканеров; детекция реализуется собственными правилами.
- LLM не определяет уязвимости и не придумывает CVE — только объясняет уже найденные проблемы.
- Секреты не должны попадать в логи, API-ответы или AI-контекст в открытом виде.
- Git scanning разрешён только для точных URL из allowlist.
- ZIP/Git checkout выполняется в workspace; запуск проектных файлов запрещён.
