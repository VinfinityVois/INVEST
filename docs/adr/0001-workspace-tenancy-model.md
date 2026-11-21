# ADR-0001 — Organization, Workspace and project ownership

- **Status:** Accepted; base schema, session context and scoped APIs implemented, remaining lifecycle/security work tracked in the backlog
- **Date:** 2026-11-21
- **Scope:** Stage 1.2 (Organizations / Workspace / Projects)

## Context

The current schema has global `Project` and `Workflow` records. `WorkflowRun` points to a workflow and `Finding` points to a run, but projects are not linked to workflows. `Credential.workspace_id` is a UUID without a foreign key to a Workspace model. The authenticated user is available in request state, but most resource endpoints do not enforce owner or tenant scope.

The current `User.is_admin` flag is a system-wide boolean, not workspace membership or tenant-scoped RBAC. Therefore the current deployment remains single-operator/trusted-environment only.

## Decision

Use four explicit levels:

1. **User** — an identity that can belong to multiple organizations.
2. **Organization** — the tenant and data ownership boundary. It has `kind = personal | organization`. Every user receives one personal organization. Team organizations may contain multiple users.
3. **Workspace** — a named working area inside an organization. A personal organization starts with one default workspace; a team organization can contain multiple workspaces.
4. **Project** — a source-code asset inside exactly one workspace.

Workflows belong to exactly one workspace and may optionally reference a project. A workflow may be useful across several projects, so project association is optional; it must never imply cross-workspace access. Runs belong to a workflow. Findings belong to runs. Reports inherit the run/workspace scope and are stored under a project only after verifying that the project and run belong to the same workspace. Credentials are workspace-scoped.

Published built-in templates and platform rule packs remain global read-only catalog data. User-created/private templates, API tokens and integrations are scoped to an organization or workspace according to their declared scope.

## Membership and roles

Use explicit organization and workspace membership records:

- `OrganizationMembership`: `owner`, `admin`, `member`.
- `WorkspaceMembership`: `admin`, `editor`, `analyst`, `viewer`.

An organization owner/admin can administer all workspaces in that organization. Other organization members receive access only to workspaces where they have a workspace membership.

Initial permission matrix:

| Action | Org owner | Org admin | Workspace admin | Editor | Analyst | Viewer |
|---|---:|---:|---:|---:|---:|---:|
| View workspace/projects/runs/findings/reports | Yes | Yes | Yes | Yes | Yes | Yes |
| Create/edit projects and workflows | Yes | Yes | Yes | Yes | No | No |
| Start/cancel/retry scans | Yes | Yes | Yes | Yes | No | No |
| Change finding state / assign / comment | Yes | Yes | Yes | Yes | Yes | No |
| Manage workspace members/settings | Yes | Yes | Yes | No | No | No |
| Manage organization members/workspaces | Yes | Yes | No | No | No | No |
| Manage organization ownership | Yes | No | No | No | No | No |
| Manage workspace credentials/integrations | Yes | Yes | Yes | No | No | No |
| Manage scoped API tokens | Yes | Yes | Yes | No | No | No |

System bootstrap access is separate from organization roles. Do not use `is_admin` as a substitute for tenant membership checks. Existing system-admin capability may be retained only for platform operations and must not automatically bypass workspace data isolation.

## Workspace context

The active workspace is stored on the server-side session (`UserSession.current_workspace_id`), not trusted from a client-provided header alone.

- On login, select the user's personal workspace if available; otherwise use the first authorized workspace.
- Switching workspace validates current membership and updates the server-side session.
- Middleware resolves the active workspace and membership for each authenticated request.
- Every project/workflow/run/finding/report/source/credential lookup must include the authorized workspace scope. Return 404 for resources outside the active workspace to avoid confirming their existence.
- CI access uses a dedicated token bound to one workflow or workspace and explicit scopes; it does not inherit browser session workspace context.
- Global catalogs are explicitly allowlisted as global and remain read-only unless a separately authorized publish action is used.

## Migration and legacy-data policy

1. Create Organization, Workspace, OrganizationMembership and WorkspaceMembership tables.
2. Create one legacy personal organization/workspace for the first active administrator and grant owner membership.
3. Backfill every existing project and workflow into that legacy workspace. Existing runs/findings inherit the scope through their workflow. A run with no workflow must be treated as an orphan and quarantined from user-facing access until explicitly assigned or purged by policy.
4. Backfill Credential.workspace_id to the legacy workspace and add the foreign key.
5. Make `projects.workspace_id` and `workflows.workspace_id` non-null after successful backfill.
6. New users receive a personal organization/workspace in the same transaction as account creation. Team organization/workspace creation is a separate authorized flow.
7. Do not auto-share the legacy workspace with every newly created account.

Migration must be tested against both an empty database and a copy of the current schema containing projects, workflows, runs, findings and credentials. Downgrade must not silently discard ownership data.

## Deactivation, deletion and ownership transfer

- User deletion is not a hard delete while the user owns an organization/workspace or has audit history.
- Deactivation revokes all sessions and blocks new authentication; existing resources remain intact.
- Before deleting a personal organization, require an export and an explicit choice to transfer or delete its workspaces/projects/runs/reports/credentials under a documented retention policy.
- An organization must always have exactly one active owner. Ownership transfer requires explicit confirmation by the current owner and an audit event.
- Workspace deletion is soft-delete first, with a retention window and export option; physical purge is a separate privileged operation.

## Required implementation sequence

1. Add schema and migration with legacy backfill.
2. Provision personal organization/workspace at bootstrap and user creation.
3. Add organization/workspace list/create/update/member APIs and UI.
4. Add active-workspace session switching.
5. Add centralized authorization helpers for organization/workspace/project/workflow/run/finding/report/credential resources.
6. Convert every resource endpoint, worker enqueue path, scheduler, SSE, report export, and CI route to scope-aware lookups.
7. Add negative API tests for cross-workspace IDOR/BOLA, including direct IDs for projects, workflows, runs, findings, reports and source files.
8. Only then enable multi-user/team access.

## Consequences

This model adds schema and request-context complexity but gives a stable tenant boundary and supports personal accounts, organizations, multiple workspaces and project-level organization. It avoids the unsafe shortcut of adding a `workspace_id` column without enforcing it throughout the API and worker.
