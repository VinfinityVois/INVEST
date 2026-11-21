# INVEST — что осталось по кейсу Центр-инвест / CyberGarden 2026

**Ветка:** `feat/platform-foundation`  
**Срез исходников:** `ecaed6c4094b07f2bddf0ea973468ade5a348d5f`  
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
| Аутентификация | Bootstrap первого admin, Argon2id, server-side sessions, HttpOnly cookie, logout, Origin check, rate limit | Реализовано на уровне single-operator |
| Отчёты | JSON и HTML export; сохранение JSON в библиотеку проекта | Реализовано частично |
| Finding lifecycle | open / accepted_risk / fixed / false_positive, причина, срок риска, история через AuditLog | Частично |

## P0 — закрыть до демонстрации

| ID | Задача | Почему ещё открыта | Критерий закрытия |
|---|---|---|---|
| P0-1 | Полный E2E на закреплённом Kotlin-репозитории | Скрипт и demo graph есть, но удалённая проверка исходников не доказывает запуск на пользовательском Docker | Один реальный прогон: Git → Secrets/SCA/SAST → Merge → AI → Webhook + Gate |
| P0-2 | Проверить webhook delivery | Реализация и тесты есть; нужен фактический приём JSON на уникальном endpoint | В webhook.site получен payload; скрипт подтвердил delivered |
| P0-3 | Проверить AI в целевом окружении | Код поддерживает provider timeout 90s, но наличие/доступность LLM credentials зависит от локального .env и сети | AI node completed, объяснения привязаны к evidence, нет configuration_required |
| P0-4 | Пересчитать benchmark на закреплённом эталоне | CI benchmarks есть, но результат ограничен конкретной версией training repo и ground truth | Сохранить precision/recall/F1 и список FP/FN для трёх сканеров |
| P0-5 | Прогнать миграции и восстановление очереди | CI и unit tests не заменяют проверку существующей пользовательской БД и рестарта worker | Upgrade на пустой и существующей БД; прерванный run восстанавливается без дублирования |

**Demo automation:** `scripts/demo.ps1` теперь входит через `/api/auth/login`, использует session cookie в памяти процесса и отзывает сессию. Для него нужны `INVEST_DEMO_EMAIL` и `INVEST_DEMO_PASSWORD`; инструкция добавлена в README и demo runbook. Сам скрипт ещё нужно выполнить локально.

## P1 — продуктовые недоделки

1. **Regex-условие.** Сейчас `logic.compare` покрывает equals/contains и числовые сравнения, но отдельного regex-оператора/ноды в реестре нет. Добавлять только если это требуется точной формулировкой задания.
2. **SCA freshness и coverage.** Maven advisory snapshot — 41 запись на 2026-11-16, не полный live feed; Spring Boot managed-version catalog ограничен выбранными версиями. Нужны безопасное обновление из upstream, проверка происхождения/хэша, diff-review и регрессионные benchmark-gates.
3. **SAST coverage.** Текущий Kotlin/Spring анализ остаётся ограниченным лексическим/эвристическим анализом с ограниченным межфайловым taint propagation; полноценные Kotlin AST/PSI, type resolution, call graph и flow-sensitive анализ отсутствуют. Не выдавать его за эквивалент промышленного компиляционного анализатора.
4. **Secrets precision.** Дальше улучшать контекст, placeholder suppression и entropy только по измерениям FP/FN; не расширять regex-набор вслепую.
5. **Reports.** Добавить CSV/SARIF в первую очередь для интеграции с CI/другими security-инструментами; PDF/XLSX — после уточнения формата, нужного жюри.
6. **Finding management.** Не хватает назначения ответственного, комментариев, labels, due date и полноценной истории переходов/повторного открытия.
7. **Audit log.** Сейчас события пишутся выборочно; нет полноценного actor-aware аудита, поиска/экспорта и tamper-evident хранения.
8. **UX.** Текущий UI приведён к CyberGarden dark visual language; остаются usability-проверка на реальных ширинах экрана, длинных finding payloads и заполненном проекте.

## P2 — обязательное до multi-user / production

- Tenant model: Organization / Workspace / Membership / Role и owner/tenant foreign keys.
- Object-level authorization на каждом API lookup; сейчас аутентифицированные пользователи не изолированы друг от друга по проектам/workflows/runs.
- Admin/user permissions; само поле `is_admin` не заменяет RBAC.
- Account lifecycle: управляемое создание пользователей, смена/сброс пароля, отключение учётной записи, отзыв всех сессий; MFA — по модели угроз.
- CSRF/origin policy и secure cookie settings проверить для реального reverse proxy/TLS deployment.
- Полный audit trail с actor identity и защитой от изменения/удаления.
- Backup/restore PostgreSQL и workspace volume, мониторинг API/worker, алерты на stuck queue, load/soak tests.
- Production deployment profile: HTTPS, secrets management, отдельные CI credentials, минимальные сетевые права.

**Важно:** текущая аутентификация закрывает анонимный доступ, но не делает приложение multi-tenant. До реализации tenant isolation не открывать сервис нескольким недоверенным пользователям и не считать его production SaaS.

## Release / branch readiness

- Ветка `feat/platform-foundation` содержит рабочую линию разработки.
- Сравнение с `main` показывает diverged history: foundation на 953 коммита впереди и на 2 коммита позади. В `main` есть отдельные revert-коммиты. Не выполнять слепой merge и не переключать default branch без анализа этих двух коммитов и согласованного PR.
- GitHub Actions на коммитах дизайна и исправления demo script проходили успешно; последний docs/runbook commit требует отдельного CI-подтверждения.
- Локальный Docker пользователя не проверен после последних удалённых изменений.

## Приоритет следующей итерации

1. Завершить CI на последнем коммите.
2. Проверить исправленный demo script на синтаксис/сценарий и обновить runbook при необходимости.
3. Провести локальный E2E на учебном репозитории и webhook; зафиксировать результаты.
4. Обновить SCA snapshot pipeline с проверяемым upstream provenance и benchmark regression.
5. После закрытия demo P0 — продолжить tenant isolation/RBAC и полный security hardening.

## Ограничения кейса, которые сохраняем

- Не использовать Semgrep, Gitleaks, Trivy, detekt или готовые rule engines вместо собственных анализаторов.
- LLM только объясняет подтверждённые сканерами findings; не обнаруживает уязвимости и не меняет Security Gate decision.
- Не использовать n8n / Node-RED как основу платформы.
- Сканировать только собственные или явно разрешённые учебные проекты.
- Не исполнять Gradle/Maven/project scripts во время анализа.
