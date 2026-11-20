# AI Security Workflow

Визуальная платформа для построения и запуска security-workflow: собственные анализаторы, AI-объяснения подтверждённых находок и уведомления.

## Архитектура

- **backend** — FastAPI, Pydantic, SQLAlchemy 2, PostgreSQL.
- **worker** — отдельный процесс исполнения графов.
- **frontend** — React, Vite, TypeScript, React Flow.
- **rules/** — собственные YAML-правила детекторов.
- **data/** — локальные справочники advisories и Spring Boot managed versions.
- **eval/** — тестовые корпуса и оценка precision/recall.

## Быстрый старт

```bash
cp .env.example .env
# Generate a 256-bit key and paste it into MASTER_KEY_HEX in .env:
python -c "import secrets; print(secrets.token_hex(32))"
docker compose up --build
```

API: http://localhost:8000/docs  
Frontend: http://localhost:5173  
Health: http://localhost:8000/health

## Текущий статус

Начальная реализация P0. Доступны редактор React Flow, реестр нод, проверка типизированных связей и циклов, базовый topological executor, сохранение workflow с версиями и первая собственная проверка секретов как отдельный модуль. SCA/SAST, постоянная очередь worker, SSE и AI-объяснения находятся в разработке.

## Принципы безопасности

- Репозитории рассматриваются как недоверенные данные: никакого запуска Gradle, Maven или скриптов проекта.
- Никаких готовых security-сканеров; детекция реализуется собственными правилами.
- LLM не определяет уязвимости и не придумывает CVE — только объясняет уже найденные проблемы.
- Секреты не должны попадать в логи, API-ответы или AI-контекст в открытом виде.
- Сканирование ограничено разрешённым allowlist целей.
