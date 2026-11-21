# INVEST — актуальный аудит исходников и roadmap

**Ветка:** `feat/platform-foundation`  
**Срез исходников:** `bd05d31d8a804535c542cc16759fb61c4af4439f`  
**Дата:** 2026-11-21  
**Метод:** статический просмотр backend, frontend, migrations, tests, CI и документации. Это не penetration test и не runtime-проверка локального Docker.

> Этот документ заменяет более раннюю оценку, в которой аутентификация ошибочно отмечалась как отсутствующая. В текущей ветке уже есть базовая single-operator authentication.

## Executive summary

Платформа содержит функциональный workflow MVP: React Flow editor, typed node registry, schema-driven config, graph validation, durable PostgreSQL worker queue, ZIP/Git sources, custom Secrets/SCA/SAST, rule packs/presets/templates, schedule trigger, compare logic, AI explanations/workflow drafts, webhook, CI gate, SSE telemetry, finding state history, run comparison и JSON/HTML reports.

Добавлены bootstrap первого администратора, Argon2id password hashing, server-side sessions, HttpOnly cookie, logout/revocation, Origin validation и database-backed login rate limits.

**Текущее состояние:** базовый tenant boundary теперь реализован для browser API: Organization/Workspace/Membership, активный Workspace в server-side session, workspace ownership у Project/Workflow, а Run/Findings/Reports наследуют scope через Workflow. Browser endpoints проверяют membership и role; CI и template publish используют API tokens, привязанные к Workspace и scopes. Это существенный переход от single-operator модели, но ещё не полный production RBAC: остаются invitations, workspace export/delete/retention, полная проверка всех фоновых/внешних путей, audit UI, backup/restore и runtime-проверки.

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
| Authentication | Bootstrap admin, Argon2id, hashed server sessions, 12h lifetime, logout, Origin checks, rate limits | Реализовано для browser account flow |
| User management | Admin create/list/search/filter/pagination/update email/role/status; profile email/password/session controls; soft deactivation revokes sessions | Реализовано частично; password recovery, MFA and deletion policy open |
| Self-service account | Password change after current-password verification; session list, revoke one/others | Реализовано в API/UI; требует runtime UX check |
| User audit events | user.created / user.updated / user.profile_updated / user.password_changed with actor_user_id | Частично; auth and all security/admin events not fully audited |
| Authorization / tenancy | Organization/Workspace/Membership, active session workspace, project/workflow ownership, scoped browser APIs and CI tokens | Реализовано базово; edge routes and full RBAC review remain |
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
- migrations `0006_user_auth`, `0007_login_rate_limits`, `0008_workspace_tenancy` and `0009_workspace_api_tokens`.

The frontend now uses the authenticated session. Demo automation was updated to log in, keep the cookie in process memory and call logout.

Remaining security boundary:
1. Organization/Workspace roles are implemented, but the role matrix is still narrower than the full product model; no invitation acceptance/email flow exists.
2. Workspace deletion/export, retention, project ownership transfer and account deletion/erasure policies remain open.
3. Browser project/workflow/run/finding/report endpoints are workspace-scoped; dedicated CI and template publishing tokens are workspace-bound and scope-checked. Continue auditing every exceptional route, scheduler/worker entry point and any future integration.
4. The platform still has a system-level `is_admin` flag for bootstrap/platform administration; it must not be used as a substitute for workspace membership.
5. Selected audit events do not yet form a complete actor-aware trail with a UI, search/export and integrity controls.
6. Password recovery/reset, MFA, key rotation, backup/restore and reverse-proxy/TLS deployment need review.

Do not expose the platform as a production SaaS until the remaining exceptional routes and background paths are reviewed, workspace IDOR/BOLA tests are exhaustive, and local runtime/restore checks are complete.

## 3. Workspace architecture and implementation state

The target Organization → Workspace → Project model is documented in [ADR-0001](./adr/0001-workspace-tenancy-model.md). Migration `0008_workspace_tenancy` creates personal organizations/workspaces for existing users, backfills legacy projects/workflows/credentials into a controlled workspace and adds ownership foreign keys. Migration `0009_workspace_api_tokens` adds scoped API tokens.

Implemented:
- personal workspace provisioning during bootstrap and admin-created user creation;
- first bootstrap admin claims the unassigned legacy workspace when no admin existed at migration time;
- active workspace is selected and stored on the server-side session;
- Organization and Workspace create/list/switch/rename APIs;
- direct membership add/list/role update/removal, organization member removal and explicit ownership transfer; membership removal and account deactivation revoke the affected workspace API tokens;
- frontend workspace selector and access-management dialog;
- workspace-scoped Project/Workflow/Run/Findings/Report browser APIs;
- source.upload graph paths must resolve to a Project in the same Workspace;
- CI run and template publish tokens are bound to a workspace, hashed at rest and checked for required scopes.

Remaining:
- email invitations and acceptance flow;
- workspace export, soft-delete, retention and organization deletion;
- complete route-by-route review of exceptional and background execution paths;
- workspace-scoped audit UI and token usage history;
- broader negative IDOR/BOLA test matrix for source files, report exports, scheduler and CI integrations;
- runtime migration and multi-user browser validation in the target Docker environment.

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

The account and workspace-management screens/APIs, cross-workspace project/workflow/run denials, API token creation/revocation and migration backfill now have CI coverage. They have not yet been exercised in the user's local Docker/browser session. Verify workspace switching, member role changes, ownership transfer, CI token scope and project file browsing against a migrated database.

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
| P1 Users / authentication | Admin user UI/API, profile, password/session controls implemented | Password recovery, deletion policy, MFA and runtime UX tests |
| P2 Organizations/RBAC | Base Organization/Workspace model and scoped APIs implemented | Complete route/background audit, invitations, export/delete and broader IDOR tests |
| P3 Dashboard | Workspace-scoped dashboard summary and UI filters/trend/recent runs implemented | Deeper finding drill-down, large-workspace performance and UX validation |
| P4 Analytics/reports | Run trends, comparison, JSON/HTML exist | CSV/SARIF, aggregate metrics |
| P5 Findings management | Basic lifecycle/history exists | Assignment, comments, labels, due dates, reopen |
| P6 AI remediation | Not confirmed | Human-approved patch proposal and diff review |
| P7 SAST | Custom Kotlin/Spring rules exist | Benchmark-driven coverage and AST/type-aware analysis |
| P8 SCA | Maven/Gradle and local snapshot exist | Upstream refresh, provenance, more ecosystems |
| P9 Collaboration | Organization/workspace membership and shared workspace access implemented; findings collaboration remains partial | Invitations, comments, assignment and collaboration audit |
| P10 Notifications | Webhook exists | Retries, signatures, delivery audit, more channels |
| P11 Audit/security | Primitives and selected events exist | Actor-aware complete audit and key lifecycle |
| P12 Production readiness | Docker/CI/worker mechanisms exist | Backup, monitoring, restore, load and deployment tests |
| P13 UX/UI | Workflow editor and refreshed CyberGarden design exist | Usability test on realistic screen sizes and data volumes |
| P14 API/integrations | Workspace-scoped API tokens with scopes/expiry/revocation; CI/template publish use scoped tokens | Usage history, rotation workflow, API versioning and external integration validation |

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
