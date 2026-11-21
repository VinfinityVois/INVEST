# План оставшихся работ — INVEST / Центр-инвест / CyberGarden 2026

**Ветка:** `feat/platform-foundation`  
**Актуальный статус:** см. [Dorabotka_Ostalos.md](./Dorabotka_Ostalos.md)  
**Последняя сверка исходников:** 2026-11-21

> Этот документ — порядок выполнения, а не утверждение, что все этапы уже пройдены. Реализация, CI и локальная runtime-проверка учитываются раздельно. Не закрывать задачу только по наличию кода.

## 0. Правила и приоритеты

1. Сначала довести пользовательский сценарий и демо до воспроизводимого MVP.
2. Затем стабилизировать миграции, worker, Docker и обработку ошибок.
3. После этого закрывать tenant isolation/RBAC и системный security hardening.
4. В конце — backup/restore, monitoring, deployment и release packaging.

Нельзя откладывать базовую безопасность: не коммитить секреты, не использовать реальные данные в тестах, не отключать allowlist/валидацию/redaction, не запускать исходники проверяемого проекта.

## 1. P0 — воспроизводимое демо и стабилизация

| ID | Задача | Текущий статус | Definition of Done |
|---|---|---|---|
| P0-1 | Учебный Kotlin/Spring E2E | Код, закреплённый demo graph и script есть; локальный прогон не подтверждён | Один run проходит Git → Secrets/SCA/SAST → Merge → AI → Webhook; trace и findings сохранены |
| P0-2 | Webhook delivery | Реализация и тесты есть; реальная доставка не подтверждена | Уникальный webhook endpoint получил ожидаемый redacted JSON |
| P0-3 | AI provider readiness | Код и timeout есть; зависит от LLM credentials/network пользователя | AI completed; explanation содержит scanner evidence; нет configuration_required |
| P0-4 | Scanner benchmark | CI jobs и ground truth есть | Сохранить precision/recall/F1, FP/FN по каждому анализатору на закреплённом commit |
| P0-5 | Миграции и queue recovery | Миграции и тесты есть; runtime на текущей БД не подтверждён | Upgrade empty/existing DB; restart worker during run; no duplicate execution |
| P0-6 | Demo automation | Скрипт обновлён для login/session/logout | Проверить PowerShell-сценарий на чистой машине и описать ожидаемые результаты |

## 2. P1 — завершение функционального MVP

| ID | Задача | Текущий статус | Следующее действие |
|---|---|---|---|
| P1-1 | Schedule trigger | Реализован | Проверить cron/timezone и duplicate suppression на нескольких worker |
| P1-2 | Conditional logic | Compare findings реализован | Отдельный regex оператор — только если он обязателен по ТЗ |
| P1-3 | Webhook | Реализован | E2E delivery, retry/signature policy при необходимости |
| P1-4 | Secrets | Реализован | Поднять precision на benchmark: context, placeholders, entropy thresholds |
| P1-5 | SCA | Реализован для Maven/Gradle | Автообновление advisory feed, provenance/hash, новые экосистемы |
| P1-6 | Kotlin/Spring SAST | Реализован ограниченный набор правил | Benchmark-driven rules; постепенно улучшать AST/type/data-flow |
| P1-7 | Typed ports | UI и backend validation есть | Добавить negative tests для всех несовместимых портов и reconnect |
| P1-8 | Schema-driven forms | Реализованы | Проверить все JSON schema типы/constraints и UX ошибок |
| P1-9 | Reports | JSON/HTML есть | CSV/SARIF для CI; затем PDF/XLSX при подтверждённой потребности |
| P1-10 | Finding management | Базовые статусы/причины/expiry/history есть | Assignment, comments, labels, due dates, reopen |
| P1-11 | UI/UX | CyberGarden design refinement внесён | Проверить реальные ширины, длинные пути, большие списки и состояния loading/error/empty |

## 3. P2 — security hardening и multi-user

| ID | Задача | Статус | Definition of Done |
|---|---|---|---|
| P2-1 | Authentication | Базовый admin login/session/rate limit есть | Account lifecycle, session management, secure deployment review |
| P2-2 | Tenant model | Не реализован | Organization/Workspace/Membership/Role и ownership foreign keys |
| P2-3 | Object-level authorization | Не реализована | Каждый API lookup проверяет tenant и permission; cross-tenant IDOR tests |
| P2-4 | Audit trail | Частичный AuditLog | Actor identity, полное покрытие событий, query/export и tamper evidence |
| P2-5 | Secrets/key management | Vault/redaction primitives есть | Rotation, recovery, backup, least privilege и operational runbook |
| P2-6 | API security | Origin checks и auth middleware есть | CSRF/reverse-proxy/TLS/header/rate-limit review и negative tests |
| P2-7 | Upload/Git/Webhook | Защитные механизмы и тесты есть | Runtime boundary tests, SSRF/DNS rebinding checks, logs/redaction audit |

**Граница безопасности:** до P2-2/P2-3 приложение остаётся single-operator/trusted deployment. Не предоставлять общий доступ нескольким недоверенным пользователям.

## 4. P3 — release readiness

- Docker Compose clean install и upgrade из предыдущей версии.
- Backup/restore PostgreSQL и workspace volume с проверкой восстановления.
- Monitoring API/worker, queue depth, stale runs, provider failures и webhook delivery.
- Load/soak tests и ограничение ресурсов для архивов, больших репозиториев и длинных workflow.
- Документация установки, обновления, rollback, bootstrap admin и rotation secrets.
- Reusable CI workflow проверить из отдельного тестового репозитория; закрепить production usage на release tag или commit SHA.
- Security review зависимостей backend/frontend и контейнерного образа.

## 5. Порядок следующих итераций

### Итерация A — demo gate
P0-1 → P0-2 → P0-3 → P0-4 → P0-5 → P0-6. Никаких новых бонусных функций до подтверждения полного прогона.

### Итерация B — scanner quality
SCA advisory refresh/provenance → SCA benchmark regression → SAST benchmark/false-positive review → Secrets precision.

### Итерация C — tenancy/security
Tenant data model → migration strategy → object-level authorization → cross-tenant tests → actor-aware audit → session lifecycle.

### Итерация D — product completion
Finding workflow → CSV/SARIF → dashboard analytics → integrations → collaboration.

### Итерация E — release
Backup/restore → monitoring → load test → deployment hardening → tagged release.

## 6. Запреты кейса

- Не использовать Semgrep, Gitleaks, Trivy, detekt или сторонний rule engine вместо собственных анализаторов.
- Не использовать LLM для детекции; AI только объясняет findings, подтверждённые сканерами.
- Не использовать n8n/Node-RED как основу.
- Не сканировать чужие production-системы.
- Не запускать Gradle/Maven/project scripts проверяемого репозитория.
- Не помещать API keys, webhook secrets и реальные пользовательские данные в тестовые fixtures или скриншоты.

## 7. Документы

- [Dorabotka_Ostalos.md](./Dorabotka_Ostalos.md) — актуальный backlog и статусы.
- [audit-current-state.md](./audit-current-state.md) — подтверждённое состояние исходников и архитектурные ограничения.
- [demo-runbook.md](./demo-runbook.md) — подготовка и полный сценарий демонстрации.
- [Rule_Packs_and_Presets.md](./Rule_Packs_and_Presets.md) — packs, presets, policies и ограничения анализаторов.
