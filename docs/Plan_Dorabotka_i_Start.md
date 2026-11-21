# INVEST — основной план завершения платформы

**Рабочая ветка:** `feat/platform-foundation`  
**Приоритет:** функциональное завершение → стабилизация → Security Hardening → Release Readiness.

Этот документ задаёт порядок работ. Подробные статусы, доказательства по исходникам и открытые дефекты ведутся в [Dorabotka_Ostalos.md](./Dorabotka_Ostalos.md), а подтверждённое техническое состояние — в [audit-current-state.md](./audit-current-state.md).

## Принципы выполнения

1. Сначала закрывать функциональные сценарии MVP. Не начинать полный системный security audit параллельно с незавершёнными пользовательскими функциями.
2. Не считать функцию готовой по наличию похожего кода: проверять UI, backend, happy path, ошибки, права доступа и тесты.
3. Базовая безопасность обязательна на каждом этапе: валидация входных данных, серверная проверка доступа, безопасные ошибки, redaction и тесты.
4. Не вводить multi-user доступ до завершения tenant ownership и object-level authorization.
5. Не использовать production data/secrets в тестах; не исполнять исходники анализируемых проектов; не отключать allowlist, валидацию или защитные проверки.
6. Не изменять `main`, не выполнять force-push, не удалять пользовательские stash без отдельного согласования.

## Этап 1 — функциональное завершение платформы

Порядок внутри этапа:

1. **Users / Accounts / Access** — завершить recovery/reset, MFA по модели угроз, политику удаления/анонимизации и полную permission matrix.
2. **Organizations / Workspace / Projects** — завершить [ADR-0001](./adr/0001-workspace-tenancy-model.md): invitations/acceptance, export, soft-delete/retention, organization deletion и полный exceptional-route/background isolation review.
3. **Findings lifecycle** — статусы, назначение ответственного, комментарии, история, массовые действия, обоснование Accepted Risk/False Positive, fingerprints и сравнение запусков.
4. **Dashboard / Analytics** — базовые workspace-scoped metrics/filter/trend/recent-runs UI реализованы; остаются глубокий drill-down, большие объёмы и UX validation.
5. **Reports / Export** — проверить JSON/HTML, затем CSV и SARIF; PDF/XLSX после фиксации требований к форматам.
6. **Audit Log** — полный перечень событий, actor identity, поиск, фильтры, экспорт и retention.
7. **API Tokens / CI/CD** — базовый UI токенов/scopes/expiry/revoke и workspace-bound CI authorization реализованы; остаются rotation workflow, usage history, docs/examples verification и audit.
8. **Backup / Restore / Administration** — backup PostgreSQL и файлов, проверенный restore, health/status и retention.
9. **Workflow / Sources / Scanners / AI / Integrations** — закрыть регрессию движка, загрузок, scanner coverage, AI и согласованные интеграции. Существующие функции не переписывать без доказанной необходимости.

### Текущий статус этапа 1

- 1.1: admin user management, profile email, password change и session controls реализованы; recovery/reset, MFA и policy удаления/анонимизации остаются открытыми.
- 1.2: базовые Organization/Workspace/Membership, active workspace session, switching, member roles, owner transfer и workspace-scoped browser APIs реализованы; invitations, export/delete/retention и полный exceptional-route review остаются открытыми.
- 1.4: базовый lifecycle findings существует; assignment/comments/bulk operations требуют завершения. Finding APIs уже ограничены active workspace.
- 1.10–1.13: JSON/HTML reports существуют; CSV/SARIF, полный audit UI, backup/restore и расширенная API token usage history требуют завершения. Workspace-scoped API tokens и CI scopes реализованы базово.

## Этап 2 — стабилизация и проверка готовности

После функционального завершения:

- CI: backend lint/type checks, unit/integration tests, frontend lint/typecheck/build, scanner benchmarks, container build; coverage thresholds для критичных модулей.
- Тестовая матрица: auth, projects, workflow, runs, findings, reports, DB, Queue/Worker, SSE, cache, tenancy, exports и scanner regression.
- E2E: login → project → source → workflow → run → findings → report; отдельно CRUD, workflow version/restore, cancel/retry, permissions и workspace isolation.
- Docker clean install, upgrade с предыдущей версии, migrations, persistence, restart policies, graceful shutdown и health checks.
- Проверка UX, производительности, больших графов/репозиториев/списков и длительных запусков.

## Этап 3 — отдельный Security Hardening

Выполнять после этапов 1 и 2 как последовательный security-проход:

1. Auth и session security: password policy, rate limits, reset, cookie, CSRF, revoke, MFA по модели угроз.
2. Authorization/RBAC/object-level access: матрица ролей, ownership, workspace isolation, IDOR/BOLA и CI token scopes.
3. CORS/Origin/CSRF: конфигурация окружений, preflight и запрещённые origins.
4. Secrets/configuration: production defaults, key rotation, secret scanning и redaction.
5. Input validation/injection: SQL/command/path/template/XSS, payload size, encoding и deserialization.
6. Uploads/source/Git: ZIP Slip, symlinks, bombs, limits, SSRF, redirects и confinement.
7. Webhook/SSRF: DNS rebinding, private IP, ports, redirects, TLS, timeout, retries и signatures.
8. Database: permissions, migrations, backup encryption, retention, isolation и pool limits.
9. AI security: prompt injection, context redaction, output schema, graph allowlist, cost/time limits и human approval for patches.
10. Logging/audit/privacy: sensitive data, trace redaction, audit integrity, retention и PII minimization.
11. Dependencies/supply chain: lockfiles, vulnerability/license scans, SBOM, image bases and provenance.
12. Infrastructure/production: HTTPS, proxy, headers, CSP/HSTS, firewall, non-root containers, monitoring and incident response.
13. Security testing: SAST, dependency/container scans, OWASP checks, threat model, issue severity and remediation of Critical/High.

## Этап 4 — Release Readiness

- Актуализировать README, architecture/API/deployment/configuration/user/workflow/scanner/CI/backup guides и troubleshooting.
- Синхронизировать backlog, audit и plan; удалить или пометить устаревшие документы.
- Подготовить release checklist: зелёный CI на release commit, backend/frontend/E2E, Docker clean install и upgrade, migrations, backup/restore rehearsal, security checklist, secrets/config review.
- Подготовить version/changelog, release artifacts, deployment и rollback plan.
- Не объявлять release-ready при непроверенных Critical/High дефектах или неподтверждённом restore.

## Definition of Done

Задача закрывается только когда:

- функция реализована в UI и backend, если применимо;
- проверены happy path и негативные сценарии;
- добавлены/обновлены unit, API или integration tests;
- проверены backend permissions и изоляция данных;
- sensitive data не попадает в logs/responses/reports;
- документация обновлена;
- CI проходит на соответствующем commit;
- нет незакрытых Critical/High дефектов по задаче;
- целевая runtime-конфигурация проверена, а непроверенные локальные сценарии явно отмечены.

## Следующий порядок работ

1. Довести CI для миграций 0008/0009, Workspace Manager и API token flows; проверить локальную миграцию и переключение workspace.
2. Завершить 1.2: invitations, workspace export/delete/retention и полный route/background isolation review.
3. Довести 1.1: recovery/reset, MFA по модели угроз, account deletion policy.
4. После стабилизации модели данных завершить Findings lifecycle, Audit Log, Reports/Export и расширить Dashboard drill-down/performance.
5. Затем Backup/Restore и оставшиеся API token usage/rotation flows.
6. Только после функционального завершения перейти к системной стабилизации, затем Security Hardening и Release Readiness.

## Связанные документы

- [Dorabotka_Ostalos.md](./Dorabotka_Ostalos.md) — текущие статусы, ограничения и оставшиеся дефекты.
- [audit-current-state.md](./audit-current-state.md) — подтверждённое состояние исходников и security boundary.
- [demo-runbook.md](./demo-runbook.md) — сценарий демонстрации.
- [Rule_Packs_and_Presets.md](./Rule_Packs_and_Presets.md) — rule packs, presets и policies.
