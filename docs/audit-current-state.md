# INVEST — актуальный аудит исходников и roadmap

**Ветка:** `feat/platform-foundation`  
**Срез исходников:** `24e09061447d3aeac140333d7fbf58235aaf3866`  
**Дата:** 2026-11-21  
**Метод:** статический просмотр backend, frontend, migrations, tests, CI и документации. Это не penetration test и не runtime-проверка локального Docker.

> Этот документ заменяет более раннюю оценку, в которой аутентификация ошибочно отмечалась как отсутствующая. В текущей ветке уже есть базовая single-operator authentication.

## Executive summary

Платформа содержит функциональный workflow MVP: React Flow editor, typed node registry, schema-driven config, graph validation, durable PostgreSQL worker queue, ZIP/Git sources, custom Secrets/SCA/SAST, rule packs/presets/templates, schedule trigger, compare logic, AI explanations/workflow drafts, webhook, CI gate, SSE telemetry, finding state history, run comparison и JSON/HTML reports.

Добавлены bootstrap первого администратора, Argon2id password hashing, server-side sessions, HttpOnly cookie, logout/revocation, Origin validation и database-backed login rate limits.

**Критическое ограничение:** authentication не равна authorization. У моделей Project/Workflow/Run/Finding нет tenant ownership и в API нет object-level permission checks. Любой вошедший пользователь потенциально видит общие данные workspace. Сейчас это single-operator/trusted environment, а не multi-tenant сервис.

## 1. Реализация по слоям

| Область | Подтверждение в коде | Оценка |
|---|---|---|
| Frontend | React, Vite, TypeScript, React Flow, design-system.css | Реализовано |
| Backend | FastAPI, Pydantic, SQLAlchemy, PostgreSQL | Реализовано |
| Workflow graph | Registry, typed ports, schema config, validator, versioning | Реализовано |
| Queue / worker | PostgreSQL locking, heartbeat, stale-run recovery logic | Реализовано; recovery требует runtime test |
| Sources | ZIP archive validation, HTTPS Git allowlist, no project execution | Реализовано |
| Secrets | Custom rules, context checks, entropy heuristics, redaction | Реализовано; precision/recall зависят от benchmark |
| SCA | Maven/Gradle parsing, advisory ranges, Spring Boot managed versions | Реализовано частично; snapshot ограничен |
| SAST | Kotlin/Spring rules and bounded interprocedural taint propagation | Реализовано частично; lexical/heuristic limits |
| AI | Explanation of scanner findings, provider readiness, workflow draft generation | Реализовано; provider E2E required |
| Schedule | Cron trigger, IANA timezone, DB schedule dispatcher | Реализовано |
| Logic | Merge and Compare findings; equals/contains/numeric operators | Реализовано; dedicated regex operator/node отсутствует |
| Notifications | HTTPS webhook with allowlist, DNS checks, no redirects/proxy trust | Реализовано; actual delivery needs demo |
| Security Gate | Named policy packs and deterministic decision | Реализовано |
| Rule packs/presets/templates | YAML inheritance, built-in preset, sanitized template publish/clone | Реализовано |
| CI | Backend tests, frontend build, scanner benchmarks, Docker, reusable security-check | Реализовано; external consumer repository setup unverified |
| Authentication | Bootstrap admin, Argon2id, hashed server sessions, 12h lifetime, logout, Origin checks, rate limits | Реализовано для single-operator |
| User management | Admin-only create/list/search/filter/pagination/update email/role/status; self-service profile email/password/session controls; soft deactivation revokes sessions | Реализовано частично; only admin/user, no deletion/recovery |
| Self-service account | Password change after current-password verification; session list, revoke one/others | Реализовано в API/UI; требует runtime UX check |
| User audit events | user.created / user.updated / user.profile_updated / user.password_changed with actor_user_id | Частично; auth and all security/admin events not fully audited |
| Authorization / tenancy | No Organization/Workspace/Membership/Role ownership model | Не реализовано |
| Finding lifecycle | open, accepted_risk, fixed, false_positive; reason, expiry, history | Частично |
| Audit log | Selected events persisted; no actor identity/full query/export/tamper evidence | Частично |
| Reports | JSON and HTML endpoints; JSON can be saved to project | Частично; CSV/SARIF/PDF/XLSX not confirmed |
| Release operations | Docker compose and CI exist | Partial; backup/restore, monitoring and load tests open |

## 2. Authentication and security boundary

Current authentication components:
- `backend/app/security/passwords.py` — Argon2id password hashing;
- `backend/app/security/bootstrap.py` and `backend/app/bootstrap_admin.py` — one-time first-admin bootstrap;
- `backend/app/security/sessions.py` — opaque random session token, SHA-256 token hash in DB, expiration and revocation;
- `backend/app/security/api.py` — login, current user, logout;
- `backend/app/security/rate_limit.py` — persistent HMAC-keyed counters, 5 attempts per email and 30 per IP per 15-minute window;
- migrations `0006_user_auth` and `0007_login_rate_limits`.

The frontend now uses the authenticated session. Demo automation was updated to log in, keep the cookie in process memory and call logout.

Remaining security boundary:
1. no tenant isolation or object-level access checks;
2. `is_admin` exists but is not a complete RBAC system;
3. basic admin user management and self-service profile email/session/password UI now exist; password recovery/reset, MFA and data deletion policy remain open;
4. selected audit events do not yet form a complete actor-aware trail;
5. operational key rotation, backup/restore and reverse-proxy/TLS deployment need review.
6. current role model is only the boolean `is_admin` mapped to admin/user; it is not workspace-scoped RBAC. Project/workflow/run/finding ownership and object-level access checks remain absent.

Do not expose this branch as a multi-user production service until tenant ownership and backend authorization are implemented and tested against IDOR/cross-tenant cases.

## 3. Workspace architecture decision

The target Organization → Workspace → Project model and membership/role matrix are documented in [ADR-0001](./adr/0001-workspace-tenancy-model.md). This is a design decision, not an implemented tenancy boundary. Current APIs still expose global project/workflow/run data to any authenticated account; do not enable untrusted multi-user access until the migration, session workspace context, endpoint scoping and cross-workspace IDOR tests are complete.

## 4. Confirmed technical limits

### SCA
- Maven advisory snapshot is a bounded benchmark-oriented dataset (41 advisories in snapshot dated 2026-11-16; see `data/README.md`).
- It is not a complete or automatically refreshed vulnerability feed.
- Spring Boot managed-version coverage is a curated subset, not a complete BOM for all releases.
- Unknown/unresolved versions must remain unknown; do not infer affected status.

### SAST
- Kotlin/Spring analysis covers selected SQL injection, TLS hostname verification, credentialed CORS, public sensitive routes and IDOR/BAC patterns.
- Taint propagation is bounded and lexical; it is not Kotlin PSI/AST, full type resolution, a complete call graph or flow-sensitive analysis.
- Keep benchmark evidence and limitations visible; do not market it as compiler-grade static analysis.

### Reports and findings
- JSON and HTML report exports exist.
- CSV, SARIF, PDF and XLSX were not confirmed.
- Finding states and history exist, but assignment, comments, labels, due dates and a complete reopen/approval process are not implemented.

## 5. Runtime verification still required

The new account-management screens and APIs are covered by CI tests/build, but have not yet been exercised in the user's local Docker/browser session. Verify admin-only access, user create/update/deactivate, session revocation and password change against a migrated database.

Source code and CI cannot prove these against the user's current environment:
- clean Docker Compose startup and health of API, DB, frontend and worker;
- Alembic upgrade from empty DB and from the user's existing DB;
- worker restart during an active run, stale lease recovery and duplicate-execution/idempotency behavior;
- full demo on the pinned Kotlin training repository: all three scanners, AI, webhook and Security Gate;
- actual webhook payload received by the unique endpoint;
- AI provider availability, timeout behavior and evidence-grounded explanation;
- secrets absence from logs, API responses, reports and webhook payload under realistic inputs;
- backup/restore of PostgreSQL and workspace volume.

The demo script `scripts/demo.ps1` requires `INVEST_DEMO_EMAIL` and `INVEST_DEMO_PASSWORD` in the current PowerShell process and now authenticates through `/api/auth/login`. See `docs/demo-runbook.md`.

## 6. Roadmap state

| Stage | Current assessment | Next action |
|---|---|---|
| P0 Audit/stabilization | Source review refreshed; local runtime still open | E2E + migrations + worker recovery |
| P1 Users / authentication | Admin user UI/API, basic status/role management, password change and session controls implemented | Password recovery, deletion policy, role matrix, tenancy and runtime UX tests |
| P2 Organizations/RBAC | Not implemented | Tenant schema, object-level authorization, IDOR tests |
| P3 Dashboard | Workflow telemetry exists; organization aggregate dashboard absent | Build after tenancy |
| P4 Analytics/reports | Run trends, comparison, JSON/HTML exist | CSV/SARIF, aggregate metrics |
| P5 Findings management | Basic lifecycle/history exists | Assignment, comments, labels, due dates, reopen |
| P6 AI remediation | Not confirmed | Human-approved patch proposal and diff review |
| P7 SAST | Custom Kotlin/Spring rules exist | Benchmark-driven coverage and AST/type-aware analysis |
| P8 SCA | Maven/Gradle and local snapshot exist | Upstream refresh, provenance, more ecosystems |
| P9 Collaboration | Not implemented | Membership, comments and shared workflows |
| P10 Notifications | Webhook exists | Retries, signatures, delivery audit, more channels |
| P11 Audit/security | Primitives and selected events exist | Actor-aware complete audit and key lifecycle |
| P12 Production readiness | Docker/CI/worker mechanisms exist | Backup, monitoring, restore, load and deployment tests |
| P13 UX/UI | Workflow editor and refreshed CyberGarden design exist | Usability test on realistic screen sizes and data volumes |
| P14 API/integrations | REST and reusable CI workflow exist | Scoped API tokens, versioning, external integration validation |

## 7. Recommended order

1. Complete local demo E2E and runtime stabilization; close P0 only with recorded evidence.
2. Implement tenant ownership and object-level authorization before inviting multiple users.
3. Expand SCA feed freshness and SAST/Secrets accuracy behind regression benchmarks.
4. Complete findings lifecycle, audit trail and export formats.
5. Finish backup/restore, monitoring, load validation and deployment documentation.

## 8. Case guardrails

- Detection must remain in INVEST's own analyzers/rules; do not substitute Semgrep, Gitleaks, Trivy or detekt.
- LLM is explanatory only. It must not discover findings or alter scanner/Gate decisions.
- Do not use n8n/Node-RED as the platform foundation.
- Scan only owned or explicitly authorized training targets.
- Do not execute Gradle, Maven or project scripts during analysis.
- Never use production data or real secrets in tests.
