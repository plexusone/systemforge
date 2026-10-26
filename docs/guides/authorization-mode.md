# Configuring the authorization mode

The `authz` key of the SystemAuth configuration selects how authorization is
evaluated. Both modes implement the same contract (organization roles,
application roles, resource grants, `ListResources`), so switching is a
configuration change. The design is in
[Authorization](../design/architecture/authorization.md#configuring-the-mode-authz-key).

## Modes

| `authz.mode` | Evaluates | Needs |
|---|---|---|
| `rbac` (default) | Roles and direct grants in process, from the membership, role and grant tables | Nothing else |
| `rebac` | Permissions derived through relationships by an engine | A relationship engine; `spicedb` is the only one |

```yaml
authz:
  mode: rebac
  engine: spicedb        # default; rebac only
  spicedb:
    mode: remote         # embedded (default) | remote
    endpoint: spicedb.internal:50051
    token: ${SPICEDB_TOKEN}
    write_schema: false  # remote only
  reconcile:             # rebac only
    interval: 15m        # 0 reconciles only at startup
```

| Key | Default | Meaning |
|---|---|---|
| `mode` | `rbac` | `rbac` or `rebac` |
| `engine` | `spicedb` | Only with `rebac` |
| `spicedb.mode` | `embedded` | `embedded` runs in process; `remote` connects over gRPC |
| `spicedb.datastore_engine` | `memory` | Embedded only: `memory` or `postgres` |
| `spicedb.datastore_uri` | | Embedded `postgres` only; required there |
| `spicedb.endpoint`, `spicedb.token` | | Remote only; `endpoint` required |
| `spicedb.insecure` | `false` | Remote without TLS; development only |
| `spicedb.write_schema` | `false` | Remote only: write the composed schema at startup. Embedded instances always get it |
| `reconcile.disabled` | `false` | `rebac` only: turn the graph reconciler off |
| `reconcile.skip_startup` | `false` | Do not reconcile at startup |
| `reconcile.interval` | `15m` | Time between reconciliations (Go duration); `0` for startup only |
| `reconcile.jitter` | a tenth of the interval | Most added at random to each interval |
| `reconcile.page_size` | `500` | Rows or relationships read per request |

## Building the provider

```go
res, err := mode.New(ctx, cfg.Authz, mode.Deps{DB: db, Registry: registry})
if err != nil { return err }
defer res.Close()

orgs := organization.NewService(db, organization.WithAuthzSyncer(res.Syncer))
invites := invite.NewService(db, baseURL,
    invite.WithAuthzSyncer(res.Syncer), invite.WithResourceGrants(res.Grants))
```

`mode.New` applies defaults, validates, and for `rebac` starts or connects to
the engine and writes the schema composed from the registered vocabularies.
`Result` carries `Provider`, `Syncer`, `SyncMode`, `Grants`, `Reconciler`,
`Schedule` and `Close()`. The membership, role and grant tables remain the
record in both modes; under `rebac` the services mirror each change into
the graph. Build one `Result` per process and give its `Syncer` and
`SyncMode` to every identity service that changes access; a service left
with the default no-op syncer writes nothing to the graph.

### The packaged SystemAuth service

`systemauthsvc.New` reads the same `authz` key and builds the mode once when
it has a database. The services it constructs (the organization, principal
and store behind SCIM, managed principals, the social login directory and
application roles) write through its syncer, with
`Options.AuthzSyncMode` (default `eventual`); the SCIM token API and
connections check with its provider; and `RunJobs` runs the reconciler at
startup and on schedule, so run `RunJobs` beside the server (the
`systemauth serve` command does). `Service.Authz()` returns the `Result`
for identity services an application constructs beside the service.
`rbac` stays the default. Connections are served in `rbac` only; a
configuration enabling them under `rebac` is refused at startup.

A host that builds `systemauth.EntStorage` itself under `rebac` passes
`systemauth.WithEntAuthzSyncer(res.Syncer, res.SyncMode)`, so that
deactivating a human through `UpdateHuman` removes their graph access; the
packaged service does this for you.

`Deps` also takes `SyncMode` (what a failed write of granted access does:
`strict` returns it, `eventual`, the default, logs it), `AccessChangeSink`,
`Logger`, `PlatformAdmin`, `ManagerRoles` and `RBACOptions`.

## Keeping the graph consistent under `rebac`

Under `rebac` the graph answers every check, so it must never grant more
than the tables record.

- **Revocations remove first.** Removing or deactivating a membership,
  lowering a role, removing an application role, resource grant, manager
  or platform administration, and deleting an organization or managed
  principal remove the relationship inside the database transaction,
  before the commit. If the graph refuses, the transaction rolls back and
  the call returns the error, in both sync modes. Nothing has changed, so
  the caller retries the same call; removing a relationship that is
  already gone succeeds.
  Deactivating a principal removes every relationship it holds (its
  memberships, application roles, resource grants, platform
  administration and the manager relations in which it is the manager)
  the same way, and demoting a member to collaborator deletes their
  application roles, removing them from the graph first. SCIM deletes a
  user only after removing its relationships, when the `scim/store`
  `Config.Syncer` is set (the packaged service sets it).
- **Grants write after, under the lock.** Adding a member, assigning a
  role or granting a resource commits first and then writes the graph,
  in a transaction holding the graph locks of the organization and the
  principal, after reading the rows again: a revocation that committed in
  between is never undone, and one that starts later waits and removes
  what was written. A failed write is returned (`strict`) or logged
  (`eventual`); the access is missing, not extra. Reactivating a
  principal writes back the relationships its rows still call for.
- **The reconciler repairs the rest.** `Result.Reconciler` compares the
  graph with the tables and writes what is missing and deletes what is
  stale: a grant whose write failed, a relationship a revocation removed
  before its commit failed, or a grant and a revocation of the same access
  that raced. It runs at startup and every 15 minutes by default; run it
  with `res.RunReconciler(ctx)` beside the application (the packaged
  SystemAuth service runs it from `RunJobs`), or on demand with
  `res.Reconciler.Reconcile(ctx)`.

```go
go func() {
    if err := res.RunReconciler(ctx); err != nil {
        logger.Error("graph reconciler stopped", "error", err)
    }
}()
```

The reconciler manages only the relationships the identity services write:
organization memberships, platform administration, manager relations,
application roles on `{app}_org` facets and resource grants on collaborator
resource types. It does not touch other relationships, such as the `org`
relation an application writes on its resources. What the tables call for
is defined once, in `identity/graphstate`, which the services also read
before a grant write: inactive memberships, deleted organizations and
deactivated principals call for no relationships, application roles count
only through an owner, admin or member membership (never a collaborator's),
and a manager relation only while the manager is active.

It is safe to run beside normal traffic and on several instances at once.
It reads the graph before the tables, so a grant committed meanwhile is not
deleted; it re-reads the rows of every relationship it deletes and writes
back one a grant committed in the meantime; and it writes a missing
relationship only while holding the same lock a revocation holds, after
reading the rows again, so it cannot restore what a revocation in progress
removed. The lock is a PostgreSQL advisory lock; on SQLite the reconciler
does not serialize with revocations.

Each run logs a summary at info level with counts only (`checked`,
`desired`, `added`, `removed`, `restored`, `skipped`); the relationships
changed, with their identifiers, are logged at debug level.
`Reconcile` returns a `ReconcileResult` with the counts per definition, and
`Reconciler.Stats()` the running totals and last error, for metrics and
alerts. Drift on every run points at failing grant writes.

## Switching from `rbac` to `rebac`

A deployment that switches starts with an empty graph. The reconciler's
startup run writes the existing memberships, application roles, grants,
managers and platform administrators from the tables; let it finish before
serving the first request, by calling `res.Reconciler.Reconcile(ctx)` before
starting the server.

## Errors

Configuration errors name the key and the accepted values and wrap
`systemauth.ErrInvalidConfig` when loaded through SystemAuth:

| Message | Cause |
|---|---|
| `authz: unknown mode "..." (want rbac or rebac)` | Mode misspelled |
| `authz: engine "..." is set but mode is rbac` | Engine given with `rbac` |
| `authz: spicedb settings are given but mode is rbac` | SpiceDB block with `rbac` |
| `authz: reconcile settings are given but mode is rbac` | Reconcile block with `rbac` |
| `authz: reconcile.interval "..."` | Interval or jitter not a Go duration, or negative |
| `authz: unknown engine "..." for mode rebac` | Engine not supported |
| `authz: spicedb.mode remote requires spicedb.endpoint` | Remote without an endpoint |
| `authz: spicedb.endpoint and spicedb.token apply to spicedb.mode remote, not embedded` | Remote keys on an embedded instance |
| `authz: spicedb.datastore_engine postgres requires spicedb.datastore_uri` | Embedded postgres without a URI |
| `authz/mode: Deps.DB is required` | `mode.New` called without a database |

At runtime, an organization API without an `Authorizer` answers `501`, and a
caller who lacks a permission answers `403` (or `404` when they cannot even
view the organization).

## Package paths

The role-based provider is `authz/rbac` and the relationship provider
`authz/rebac/spicedb`. The former `authz/simple` and `authz/spicedb`
paths are deprecated forwarders and will be removed in the next major
release.
