# INVEST — что осталось по кейсу Центр-инвест / CyberGarden 2026

**Ветка:** `feat/platform-foundation`  
**Срез исходников:** `4f5aff998f3999e48b8275f9a617ba0f5aa677da`  
**Дата:** 2026-11-21  
**Метод:** повторная проверка исходников, тестов, workflow и документации GitHub. Это не локальный E2E-прогон и не penetration test.

## Короткий вывод

Функциональный workflow-MVP уже существенно шире раннего плана: расписание, compare-фильтр, typed ports, schema-driven config, шаблоны, AI-черновик графа, CI reusable workflow, аутентификация администратора и отчёты JSON/HTML присутствуют в коде.

Главные незакрытые вещи сейчас — не добавление ещё десятка нод, а **проверяемая демонстрация полного сценария**, актуальность SCA-данных, точность анализаторов на эталоне, безопасная модель доступа и release readiness.

## Что подтверждено реализованным

| Область | Текущее состояние | Статус |
|---|---|---|
| Workflow editor | React Flow, сохранение графа/версий, запуск, live SSE/telemetry | Реализовано |
| Источники | ZIP и allowlisted HTTPS Git, ограничения распаковки, код не исполняется | Реализовано |
| Триггеры | Manual и cron schedule с IANA timezone | Реализовано |
| Анализаторы | Собственные Secrets, Maven/Gradle SCA, Kotlin/Spring SAST | Реализовано; полнота ограничена |
| Логика | Merge и Compare findings с фильтрами/операторами | Реализовано; отдельного regex-блока нет |
| Типы связей | UI проверяет совпадение типов портов; backend валидирует граф | Реализовано |
| Формы настроек | Поля строятся по config schema манифеста | Реализовано |
| AI | Объяснение находок и генерация черновика workflow | Реализовано; нужна проверка провайдера на демо |
| Уведомления | HTTPS webhook с allowlist/DNS-проверками и ограниченным payload | Реализовано; доставка требует E2E |
| Security Gate | Профили политик и независимое решение по findings | Реализовано |
| Rule packs / presets / templates | YAML packs, preset-каталог, публикация/поиск/clone templates | Реализовано |
| CI/CD | Reusable security-check workflow и CI job в проекте | Реализовано; подключение из внешнего репозитория требует проверки |
| Аутентификация | Bootstrap admin, Argon2id, server-side sessions, HttpOnly cookie, Origin check, rate limit | Реализовано для базовой учётной записи |
| Пользователи / аккаунты | Admin UI: создание, поиск, фильтры, пагинация, изменение email/роли, блокировка; self-service profile email, password change и session list/revoke | Реализовано базово; reset/recovery и политика удаления открыты |
| Session lifecycle | Просмотр сессий, завершение одной/остальных; смена пароля отзывает остальные; блокировка пользователя отзывает все сессии | Реализовано в API/UI; требуется runtime UX-проверка |
| User audit | user.created / user.updated / user.profile_updated / user.password_changed; workspace/member/token events | Частично; нет полного audit UI, login/logout trail and export |
| Отчёты | JSON и HTML export; сохранение JSON в библиотеку проекта | Реализовано частично |
| Finding lifecycle | open / accepted_risk / fixed / false_positive, причина, срок риска, история через AuditLog | Частично |

## Этап 1 — оставшиеся функциональные задачи

### 1.2 Workspace model — базовая реализация выполнена

Целевая модель зафиксирована в [ADR-0001](./adr/0001-workspace-tenancy-model.md). В коде уже есть миграции `0008_workspace_tenancy` и `0009_workspace_api_tokens`, personal Organization/Workspace provisioning, legacy backfill, server-side active workspace, membership roles, UI selector/manager, owner transfer, workspace-bound API tokens и scoped CI/template publish.

Закрыто в базовом варианте:
- Organization → Workspace → Project; Project/Workflow имеют `workspace_id`, Workflow может ссылаться на Project.
- Run/Findings/Reports наследуют scope через Workflow; orphan runs не доступны через browser API.
- Project, workflow, run, finding lifecycle, report и source upload endpoints проверяют активный Workspace.
- CI tokens привязаны к одному Workspace и проверяют scopes `workflow:run` / `run:read`; template publish требует `template:publish`.
- UI: переключение Workspace, создание Organization/Workspace, добавление существующего пользователя, управление workspace role, отзыв membership, transfer ownership, создание/revoke API token.

Остаётся:
1. email invitations/acceptance и приглашение новых пользователей;
2. workspace export, soft-delete, retention и organization deletion;
3. полный маршрутный review exceptional endpoints, scheduler/worker и integrations;
4. расширенная IDOR/BOLA матрица для source files, reports, CI, schedule и bulk operations;
5. audit UI, token usage history и event retention.

### Другие функциональные пробелы

1. **Regex-условие.** Сейчас `logic.compare` покрывает equals/contains и числовые сравнения, но отдельного regex-оператора/ноды в реестре нет. Добавлять только если это требуется точной формулировкой задания.
2. **SCA freshness и coverage.** Maven advisory snapshot — 41 запись на 2026-11-16, не полный live feed; Spring Boot managed-version catalog ограничен выбранными версиями. Нужны безопасное обновление из upstream, проверка происхождения/хэша, diff-review и регрессионные benchmark-gates.
3. **SAST coverage.** Текущий Kotlin/Spring анализ остаётся ограниченным лексическим/эвристическим анализом с ограниченным межфайловым taint propagation; полноценные Kotlin AST/PSI, type resolution, call graph и flow-sensitive анализ отсутствуют. Не выдавать его за эквивалент промышленного компиляционного анализатора.
4. **Secrets precision.** Дальше улучшать контекст, placeholder suppression и entropy только по измерениям FP/FN; не расширять regex-набор вслепую.
5. **Account lifecycle.** Password reset/recovery, MFA, policy удаления/анонимизации и проверка account deletion remain open.
6. **Reports.** Добавить CSV/SARIF в первую очередь; PDF/XLSX — после уточнения формата.
7. **Finding management.** Не хватает назначения ответственного, комментариев, labels, due date и полноценной истории переходов/повторного открытия.
8. **Audit log.** Нет полноценного actor-aware audit UI, поиска/экспорта, tamper-evident хранения и retention controls.
9. **UX.** Остаются usability-проверки на реальных ширинах экрана, длинных finding payloads и заполненном проекте.


## Этап 2 — стабилизация и подтверждение демо

| ID | Задача | Почему ещё открыта | Критерий закрытия |
|---|---|---|---|
| P0-1 | Полный E2E на закреплённом Kotlin-репозитории | Скрипт и demo graph есть, но удалённая проверка исходников не доказывает запуск на пользовательском Docker | Один реальный прогон: Git → Secrets/SCA/SAST → Merge → AI → Webhook + Gate |
| P0-2 | Проверить webhook delivery | Реализация и тесты есть; нужен фактический приём JSON на уникальном endpoint | В webhook.site получен payload; скрипт подтвердил delivered |
| P0-3 | Проверить AI в целевом окружении | Код поддерживает provider timeout 90s, но наличие/доступность LLM credentials зависит от локального .env и сети | AI node completed, объяснения привязаны к evidence, нет configuration_required |
| P0-4 | Пересчитать benchmark на закреплённом эталоне | CI benchmarks есть, но результат ограничен конкретной версией training repo и ground truth | Сохранить precision/recall/F1 и список FP/FN для трёх сканеров |
| P0-5 | Прогнать миграции и восстановление очереди | CI и unit tests не заменяют проверку существующей пользовательской БД и рестарта worker | Upgrade на пустой и существующей БД; прерванный run восстанавливается без дублирования |

**Demo automation:** `scripts/demo.ps1` теперь входит через `/api/auth/login`, использует session cookie в памяти процесса и отзывает сессию. Для него нужны `INVEST_DEMO_EMAIL` и `INVEST_DEMO_PASSWORD`; инструкция добавлена в README и demo runbook. Сам скрипт ещё нужно выполнить локально.


## Этап 3 — security hardening и границы multi-user

- Довести route-by-route security review и отрицательные IDOR/BOLA tests для всех exceptional endpoints, scheduler/worker и bulk operations.
- Закончить invitations, workspace export/delete/retention и organization deletion policy.
- Admin/user permissions; само поле `is_admin` не заменяет workspace-scoped RBAC.
- Account lifecycle: создание/редактирование/блокировка, смена пароля и session revocation реализованы в базовом виде; остаются recovery/reset, MFA по модели угроз, безопасное удаление/анонимизация и проверка целевых UX-сценариев.
- CSRF/origin policy и secure cookie settings проверить для реального reverse proxy/TLS deployment.
- Полный audit trail с actor identity и защитой от изменения/удаления.
- Backup/restore PostgreSQL и workspace volume, мониторинг API/worker, алерты на stuck queue, load/soak tests.
- Production deployment profile: HTTPS, secrets management, отдельные CI credentials, минимальные сетевые права.

**Важно:** базовая workspace isolation уже есть, но не завершён полный security review и lifecycle организаций/приглашений. Не считать платформу production SaaS до закрытия оставшихся IDOR/BOLA сценариев, exceptional routes, backup/restore и runtime проверки.

## Release / branch readiness

- Ветка `feat/platform-foundation` содержит рабочую линию разработки.
- Сравнение с `main` показывает diverged history: foundation на 953 коммита впереди и на 2 коммита позади. В `main` есть отдельные revert-коммиты. Не выполнять слепой merge и не переключать default branch без анализа этих двух коммитов и согласованного PR.
- CI backend/frontend/benchmarks/container проходит на промежуточных коммитах workspace implementation; новые migration/token/UI changes ещё ожидают финального зелёного run.
- Локальный Docker пользователя не проверен после последних удалённых изменений.

## Приоритет следующей итерации

1. Довести CI для миграции 0009, scoped API tokens и Workspace Manager; устранить regressions.
2. Проверить локально миграции 0008/0009, переключение Workspace, роли и CI token scope.
3. Провести полный E2E на учебном репозитории и webhook; зафиксировать результаты.
4. Закрыть invitations, workspace export/delete/retention и account recovery/deletion policy.
5. Обновить SCA snapshot pipeline с проверяемым upstream provenance и benchmark regression.

## Ограничения кейса, которые сохраняем

- Не использовать Semgrep, Gitleaks, Trivy, detekt или готовые rule engines вместо собственных анализаторов.
- LLM только объясняет подтверждённые сканерами findings; не обнаруживает уязвимости и не меняет Security Gate decision.
- Не использовать n8n / Node-RED как основу платформы.
- Сканировать только собственные или явно разрешённые учебные проекты.
- Не исполнять Gradle/Maven/project scripts во время анализа.
