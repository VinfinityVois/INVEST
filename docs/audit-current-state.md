# INVEST — source audit and roadmap status

**Branch:** `feat/platform-foundation`  
**Audited revision:** `b9c1d8a561f786be58eef9f4bba612c0eca30f72`  
**Audit date:** 2026-11-21  
**Scope:** source-level review of the current backend, frontend, persistence, migrations, tests and CI. This is not a penetration test and does not replace runtime verification against the local Docker environment.

## Executive summary

The repository already contains a substantial single-workspace workflow MVP: a React Flow editor, typed node registry and graph validation, persistent projects/workflows/runs, a PostgreSQL-backed worker queue, SAST/SCA/secrets scanners, rule packs and presets, AI explanations/workflow generation, run telemetry and comparisons, JSON/HTML reports, finding-state updates, webhook delivery and workflow templates.

The most important product/security gap is that the current application has **no user authentication or tenant authorization layer**. The API exposes project, workflow, run, finding and report operations without a user/session dependency. The current data model has no User, Organization, Membership, Workspace or Role tables. The current application must therefore be treated as a trusted local/single-operator MVP, not exposed as a multi-user service to an untrusted network.

## 1. Confirmed implementation map

| Area | Source evidence | Status |
|---|---|---|
| FastAPI backend | `backend/app/main.py`, `backend/app/config.py` | Implemented |
| React/Vite frontend and React Flow editor | `frontend/src/App.tsx`, `frontend/src/main.tsx` | Implemented |
| Typed workflow node registry and config schemas | `backend/app/workflows/registry.py`, `schemas.py`, frontend schema-driven controls | Implemented |
| Workflow graph validation and execution | `backend/app/workflows/validator.py`, `engine.py` | Implemented |
| Durable worker queue | `backend/app/queue.py`, `worker.py`; PostgreSQL row locking, heartbeat and stale-run recovery logic | Implemented; runtime recovery still needs verification |
| Persistent projects and workflow versions | `Project`, `Workflow`, `WorkflowVersion` models and API routes | Implemented |
| Finding persistence and basic states | `Finding`, `FindingState`; open, accepted_risk, fixed, false_positive | Partial lifecycle |
| Scanner implementations | `backend/app/scanners/secrets.py`, `sca.py`, `sast.py` | Implemented; coverage/precision need benchmarks |
| Rule packs and presets | `backend/app/rules_loader.py`, `backend/app/workflows/presets.py`, `rules/`, `presets/` | Implemented |
| AI explanations and workflow draft generation | `backend/app/ai/` | Implemented; provider outage degrades run to partial |
| Run telemetry, trends and run comparison | API routes in `backend/app/main.py` | Implemented |
| Reports | JSON and HTML export endpoints | Partial; PDF/CSV/XLSX/SARIF not confirmed |
| Workflow schedules | `WorkflowSchedule`, schedule API and queue scheduling | Implemented |
| Workflow templates | sanitized publish/list/clone flow | Implemented |
| Webhook notifications | `backend/app/notifications/webhook.py` | Implemented; delivery security tests exist |
| Audit log storage | `AuditLog` model and selected write events | Partial; no complete audit query/API or actor identity |
| Credential vault and redaction | `backend/app/security/vault.py`, `redaction.py` | Implemented; operational key management needs review |

## 2. P0 — stabilization findings

### Confirmed by source inspection

- Four Alembic revisions exist: `0001_initial` through `0004_workflow_templates`.
- Backend tests cover workflow execution/validation, queue behavior, SQLite schema compatibility, archive validation, Git source allowlisting, webhook SSRF controls, vault behavior, redaction, scanners, presets and AI provider degradation.
- CI has backend pytest, frontend TypeScript/Vite build, three scanner benchmark jobs and a Docker image build.
- ZIP extraction has explicit size/count/ratio and path validation limits in the archive implementation and associated tests.
- Git source requires HTTPS and an exact allowlisted repository; tests cover unsafe URL/ref rejection.
- Webhook delivery validates allowed hosts and public DNS resolution, disables redirects and environment proxy trust; tests cover these cases.
- Existing `AuditLog` writes cover selected project/report/workflow events, but this is not a complete security audit trail.

### Critical gaps confirmed by source inspection

1. **No authentication:** no registration/login/logout/session/refresh-token endpoints or user model were found.
2. **No backend authorization:** API route handlers do not use a current-user dependency or object-level permission checks. CORS is not an authorization control.
3. **No tenant model:** there are no Organization, Membership, Workspace or Role entities and no tenant foreign keys on projects/workflows/runs/findings.
4. **No account security controls:** no password hashing, email verification, password reset, MFA, session revocation or login rate limiting were found.
5. **Audit coverage is incomplete:** no actor identity, comprehensive event coverage, audit query API or tamper-evidence mechanism was found.
6. **Report formats are incomplete:** JSON and HTML are present; PDF, CSV, XLSX and SARIF export were not found in the reviewed API.
7. **Findings lifecycle is partial:** current persisted states are open, accepted_risk, fixed and false_positive. Assignment, comments, labels, due dates, state-transition history and explicit reopen handling are not yet a complete workflow.

**Deployment warning:** until authentication and object-level authorization are implemented, do not expose the API/UI to an untrusted network or treat the current service as a multi-user/production deployment.

### Runtime checks still required

These cannot be proven from static source review alone and remain open:

- clean Docker Compose startup from an empty environment;
- Alembic upgrade from an empty database and upgrade of an existing database snapshot;
- worker restart during a running job, stale lock recovery and duplicate execution/idempotency behavior;
- actual ZIP boundary tests at configured limits;
- end-to-end verification of Git allowlist and webhook SSRF protections in the deployed container/network;
- confirmation that secrets are absent from application logs, API responses and generated reports under realistic inputs;
- full local backend tests, frontend build and benchmark execution in the user's current checkout.

## 3. CI status at audited revision

GitHub Actions reported the CI workflow as **completed / success** for revision `b9c1d8a561f786be58eef9f4bba612c0eca30f72` on 2026-11-21. The workflow contains backend tests, frontend build, scanner benchmarks and container build.

This CI result does not prove local Docker runtime behavior, production security, database upgrade safety or the user's current local configuration.

## 4. Roadmap state

| Roadmap stage | Current assessment | Next action |
|---|---|---|
| P0 Audit & stabilization | Source audit completed; runtime checks remain open | Run local integration checklist and close any regressions |
| P1 Authentication | Not implemented | Design and implement secure accounts, sessions and recovery |
| P2 Organizations & RBAC | Not implemented | Add tenant model and enforce backend object-level permissions |
| P3 Dashboard | Partial workflow/run telemetry exists; organization-wide dashboard not confirmed | Build aggregate APIs after tenancy foundation |
| P4 Analytics & Reports | Workflow trend and JSON/HTML reports exist | Add aggregate metrics and export formats |
| P5 Findings Management | Basic state updates exist | Add lifecycle history, assignment, comments and risk expiry |
| P6 AI Remediation | Not confirmed | Design patch proposal/approval pipeline with human control |
| P7 SAST expansion | Existing Kotlin SAST and rule packs | Improve AST/data-flow coverage against benchmarks |
| P8 SCA expansion | Existing Maven/Gradle support and local advisory data | Improve resolution/advisory freshness and add ecosystems |
| P9 Collaboration | Not implemented | Build on organizations, membership and notifications |
| P10 Notifications | Webhook exists | Add signed delivery, retries and additional channels |
| P11 Audit & Security | Partial audit and security primitives exist | Complete actor-aware audit trail and security controls |
| P12 Production readiness | Partial CI/worker health mechanisms | Add monitoring, backup/restore, deployment and load validation |
| P13 UX/UI | Workflow editor and CyberGarden design exist | Add product pages as backend capabilities land |
| P14 API & integrations | REST API and webhook exist | Add scoped API tokens, integrations and versioning |

## 5. Recommended implementation sequence

1. Close P0 runtime verification and address any regressions.
2. Implement P1 authentication before exposing the service to multiple users.
3. Implement P2 organizations, memberships and backend RBAC before aggregate dashboards.
4. Build P3 dashboard and P5 findings management on tenant-scoped data.
5. Expand P4 reports and analytics.
6. Implement AI remediation with diff review and explicit human approval.
7. Continue SAST/SCA coverage improvements using reproducible benchmark gates.
8. Complete collaboration, notifications, audit and production readiness.

## 6. Architectural guardrails for the next milestones

- Every tenant-owned record must be scoped on the backend; never rely on frontend filtering.
- Every object lookup must verify membership/permission to prevent IDOR and cross-tenant access.
- Add migrations with upgrade/downgrade tests and preserve existing SQLite compatibility where supported.
- Keep AI-generated content advisory; scanner evidence and security-gate decisions remain deterministic and independently auditable.
- Treat code, findings, repository metadata and webhook responses as untrusted input.
- Do not mark a milestone complete until automated tests and a local end-to-end verification pass.
