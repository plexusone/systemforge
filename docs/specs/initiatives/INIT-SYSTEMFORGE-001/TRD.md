# TRD — Unified Forge Platform — Authorization Contract, IAM Console, and Shell Composition

**Initiative:** `INIT-SYSTEMFORGE-001`
**Status:** Draft

## Current State

- **systemforge** (`github.com/plexusone/systemforge`): `authz` package with
  `Principal`/`Action`/`Resource`, `Authorizer` interface, simple
  role-hierarchy and SpiceDB providers, HTTP middleware; `identity` with a
  token service carrying `Scopes []string` and principals with
  `AllowedScopes`; `multiapp` schema-per-app hosting; `marketplace`.
- **systemforge-web** (`github.com/plexusone/systemforge-web`): pnpm workspace
  with `@plexusone/shell` (AppShell, Navbar, Sidebar, OrgSwitcher,
  UserMenu, ShellContext; `NavItem.roles` already exists), `@plexusone/auth`
  (BFF), `@plexusone/tenant`, `@plexusone/pages` (Login, OrgMembers,
  OrgInvitations, OrgSettings, UserSettings), design-tokens, telemetry,
  api-client. agentforge-web consumes `@plexusone/auth` today.
- **Forge authz state**: ActionForge has an `authz` package implementing the
  target conventions (this initiative hoists them); DashForge has a SpiceDB
  schema with unprefixed definitions (collision risk) and owner/admin/editor/
  viewer + publisher-side creator/reviewer roles; AgentForge has runtime tool
  policy only, no org-role vocabulary.

## Design

### 1. Authorization contract (systemforge)

A convention doc (`docs/authz-conventions.md`) plus a small vocabulary
interface in `authz`:

```go
// AppVocabulary is what each Forge app registers with the platform.
type AppVocabulary interface {
    App() string                       // "actionforge"
    Roles() RolePermissions            // role -> dotted permissions
    Hierarchy() RoleHierarchy
    Scopes() []string                  // "{app}:{resource}:{verb}", "{app}:admin"
    SpiceDBSchema() string             // "{app}_"-prefixed definitions only
}
```

Conventions (normative):

- Resource types: `{app}.{resource}` (e.g. `actionforge.run`).
- Scopes: `{app}:{resource}:{verb}`; `{app}:admin` implies all app scopes;
  scopes gate credentials, roles gate principals; effective access is the
  intersection (two-gate model).
- Roles: canonical `owner(100)/admin(80)/editor(60)/viewer(20)` shared across
  apps; app domain roles slot between (ActionForge `approver(50)`,
  `developer(40)`; DashForge `creator`, `reviewer`), and separation-of-duties
  pairs are documented per app.
- SpiceDB: SystemForge owns base definitions `principal`, `organization`
  (generic membership relations), `platform`; app schemas contribute only
  `{app}_`-prefixed definitions that reference the base (e.g.
  `actionforge_workflow { relation org: organization }`). A registry helper
  concatenates base + registered app schemas and validates for duplicate
  definitions.

### 2. IAM console

Backend (systemforge): admin APIs over existing services —
role-assignment CRUD per (org, principal, app), vocabulary introspection
(`GET /admin/apps` → each registered AppVocabulary's roles/permissions/
scopes), and token/API-key issuance constrained to the principal's
`AllowedScopes` (already modeled in identity).

Frontend (systemforge-web): new IAM pages in `@plexusone/pages` (or a
dedicated `@plexusone/iam`): Members (role assignment per app),
Roles & Permissions (matrix rendered from vocabulary introspection — apps
appear automatically), API Keys & Tokens (scope picker grouped by app,
consent-screen style). ReBAC relationship browser (SpiceDB read API) is
follow-on.

### 3. Shell composition (micro-frontend decision)

**Decision: build-time composition now; contract designed so runtime MFE can
be added later without app changes.** Rationale: all Forge UIs share one
stack (React + `@plexusone/*`), one team, one release train — Module
Federation's costs (version skew, shared-dep pinning, runtime failure modes)
buy nothing today. The registration contract is the stable seam:

```ts
export interface ForgeApp {
  id: string;                    // "actionforge"
  title: string;
  navSections: NavSection[];     // items carry roles?/scopes? gating
  routes: ForgeRoute[];          // path -> lazy component
  requiredScopes?: string[];     // hidden entirely if session lacks these
}
registerForgeApp(app: ForgeApp)
```

`@plexusone/shell` renders the union of registered apps' nav (gated by the
session's role/scopes), mounts routes under the shared chrome, and owns
session/org context. Lazy route components keep per-app code split even in a
single build. If independent deployment is later required, the same
`ForgeApp` object is what a Module Federation remote would expose.

Customer-embedded mode (embedding one capability into a third-party SaaS) is
explicitly a different mechanism — iframe/web-component + scoped token — and
is specced per-app as follow-on, not via the shell.

**Contract as specified.** The registration contract is specified in
`INIT-SYSTEMFORGEWEB-001` as `AppModule` and `Shell` in `@plexusone/host`.
`ForgeApp`'s fields map onto it: `id` and `title` are `id` and `name`,
`navSections` is `navigation(context)`, and `routes` are the module's routes
under `/orgs/:org`. Role gating is per application, from the session's
membership roles, rather than by scopes. Instead of registering into one
shell, a stack composes modules with its own `Shell` through
`createHost({ apps })` for one build, or `createHost({ app })` per host, so
the same application also runs on its own in a neutral `DevShell`.

## Risks

- **DashForge schema migration is breaking** for any existing SpiceDB data
  (definition renames rewrite relationships). Mitigated: DashForge deployment
  is pre-production; migrate before real tenants.
- **Vocabulary drift between simple-provider grants and SpiceDB schemas**
  (two expressions of the same rules). Mitigated by per-app consistency tests
  (ActionForge already has one) and by the registry validating apps at
  startup.
- **Shell contract over-fitting to today's three apps.** Mitigated by keeping
  `ForgeApp` minimal (nav, routes, scopes) and versioning it from day one.

## Testing Strategy

- systemforge: unit tests for vocabulary registry (duplicate-definition
  detection, scope-format validation); admin API tests over the simple
  provider.
- systemforge-web: component tests for IAM pages against a mocked api-client;
  the reference host app is the integration proof (one login, two apps,
  role/scope-gated nav).
- Per-Forge adoption RMIs each carry their own conformance test (schema
  prefix check, scope naming check) so drift fails CI in the app repo.
