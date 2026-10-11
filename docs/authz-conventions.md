# Cross-Forge Authorization Conventions

SystemForge is the authorization substrate for every Forge application
(ActionForge, AgentForge, DashForge, and future apps). This document is the
**normative contract** an application implements so that a composed
deployment has one identity, one role model, one token-scope convention, and
one ReBAC schema. The programmatic form of this contract is
`authz.AppVocabulary`; registering a vocabulary validates it against these
rules (`authz.ValidateVocabulary`) and is what makes an app administrable in
the IAM console.

## The two-gate model

Every API operation is guarded by two independent checks, and **both must
pass**:

1. **Role gate** — the principal's role in the organization must grant the
   operation's permission: *may this person ever do this?*
2. **Scope gate** — the presenting credential's OAuth scopes must include the
   operation's scope: *may this credential do it right now?*

Effective access is the intersection (the standard OAuth resource-server
model): an org admin using a token scoped to `actionforge:runs:read` is
read-only on that token.

## Naming

| Surface | Convention | Example |
| --- | --- | --- |
| App identifier | short lowercase, `^[a-z][a-z0-9]{1,31}$` | `actionforge` |
| Resource type | `{app}.{resource}` | `actionforge.run` |
| Permission | dotted `{resource}.{verb}` | `run.approve` |
| OAuth scope | `{app}:{resource}:{verb}` | `actionforge:runs:approve` |
| Blanket scope | `{app}:admin` implies all app scopes | `dashforge:admin` |
| SpiceDB definition | `{app}_{name}` | `actionforge_workflow` |

Scopes are namespaced per app so a host SaaS can issue a token for exactly
the embedded capability it exposes. A scope never crosses apps; grant
multiple scopes instead.

## Roles

There are three kinds of role, and they do not share a ladder.

**Organization roles** are the platform's: `owner(100) / admin(80) /
member(40) / collaborator(20)`. `owner`, `admin` and `member` are
organization-wide: they grant the permissions of the base `organization`
definition (`manage`, `edit`, `contribute`, `view`, `list`, and the
administrative ones). A `collaborator` has no organization-wide access: it
holds only `list`, so an application can show the organization in a
switcher, and reaches individual resources through resource roles (below).
`editor` and `viewer` are not organization roles; the 0008 migration mapped
existing ones to `member` and `collaborator`.

**Application roles** are an application's own (ADR-007), assigned per
organization and declared in its vocabulary. Apps may add **domain roles**
where the domain demands them, slotted into the hierarchy; every role must
appear in both `Roles()` and `Hierarchy()`. An application role is not an
organization role, so an application may name one `viewer` or `editor`.

Domain roles exist for **separation of duties**, and each app must document
its pairs. The canonical example is ActionForge's approval gate:

- the application's `editor` role can change and trigger workflows but
  **cannot** approve gates;
- `approver(50)` can approve gates but **cannot** edit or trigger;
- only `admin`/`owner` hold both sides.

The same separation applies at the scope level: `actionforge:runs:write`
deliberately does **not** imply `actionforge:runs:approve`, so a CI bot can
trigger pipelines but can never release a production gate.

### Resource roles

A resource type that accepts collaborators uses one standard ladder of
**resource roles**, so every application means the same thing by them. The
names are reserved:

| Resource role | Grants |
| --- | --- |
| `viewer` | read the resource (`view`) |
| `contributor` | also change it and create items within it (`edit`) |
| `maintainer` | also manage its settings and its collaborators (`manage`) |

Each role includes the ones below it: `viewer < contributor < maintainer`.
The permission names a fragment exposes for them are `view`, `edit` and
`manage`. `admin` on a resource is **not** a resource role: it is an
application role, held organization-wide.

A resource definition declares all three relations, binds them to
`principal`, and has an `org` relation to `organization`, so members keep
their organization-wide access and a collaborator has only the direct
relations:

```zed
definition myapp_project {
    relation org: organization
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal

    permission view   = viewer + contributor + maintainer + org->view
    permission edit   = contributor + maintainer + org->edit
    permission manage = maintainer + org->manage
}
```

A definition that declares some of the three but not all, or binds one to
anything but `principal`, or has no `org` relation to `organization`, is
refused when the vocabulary is registered (`authz.ValidateAppSchema`).
Granting a resource role to a principal who is not a member of the
resource's organization makes them a `collaborator` of it; revoking their
last grant there removes the membership. A grant is by `{app}_{type}` and
the application's own resource identifier, in the organization that owns
the resource; a resource does not change organization through a grant.

## SpiceDB: base + facets

SystemForge owns the base definitions (`authz.BaseSpiceDBSchema`):
`principal`, `organization` (membership ladder: `manage`/`edit`/`contribute`/
`view`/`list` plus org administration), and `platform`. **Apps never redefine
these.**

The base `principal` definition carries the manager relations of
[managed principals](identity/managed-principals.md): `guardian` and
`educator`, with the platform permissions `manage_account`,
`manage_credentials`, `view_profile`, and `manage_managers`. Apps reference
them (for example `learner->view_profile`) rather than inventing
`parent`/`teacher` relations of their own; the simple provider applies the
same grants through `authz.ManagerRolePermissions`.

An app attaches through a *facet*: an `{app}_org` definition that references
the shared `organization` and adds the app's domain-role relations:

```zed
definition actionforge_org {
    relation org: organization
    relation approver: principal
    relation developer: principal

    permission workflow_read = org->view
    permission workflow_write = org->edit
    permission workflow_trigger = org->edit + developer
    permission run_approve = org->manage + approver
}

definition actionforge_workflow {
    relation app_org: actionforge_org
    permission read = app_org->workflow_read
    permission write = app_org->workflow_write
    permission trigger = app_org->workflow_trigger
}
```

Generic membership flows through the arrows (`org->view`); domain roles are
relations on the facet. Every definition an app contributes must carry the
`{app}_` prefix — validated at registration, and re-checked by
`VocabularyRegistry.ComposeSpiceDBSchema`, which assembles base + all
registered fragments into the deployment schema.

An app that only supports the simple role-hierarchy provider returns an
empty `SpiceDBSchema()`; both providers must express the same grants, and
each app should carry a consistency test asserting so.

## Conformance checklist (per app)

1. Implement `authz.AppVocabulary`; register it at startup.
2. Scopes pass `authz.ValidateScope`; schema passes
   `authz.ValidateAppSchema` (enforced by `Register`).
3. Simple-provider grants and the SpiceDB fragment express identical rules
   (app-local consistency test).
4. Separation-of-duties pairs documented in the app's authz package.
5. API routes declare (permission, scope) pairs and enforce the two-gate
   model.

Adoption status: ActionForge (`actionforge/authz`, aligning to the facet
pattern), DashForge (schema re-namespace pending), AgentForge (vocabulary
pending).
