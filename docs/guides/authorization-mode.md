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
`Result` carries `Provider`, `Syncer`, `Grants` and `Close()`. The
membership, role and grant tables remain the record in both modes; under
`rebac` the services mirror each change into the graph.

`Deps` also takes `SyncMode` (`strict` returns a graph write failure,
`eventual`, the default, logs it), `AccessChangeSink`, `Logger`,
`PlatformAdmin`, `ManagerRoles` and `RBACOptions`.

!!! warning "Failed revocations under `rebac`"
    The services commit the database change before writing the graph, and
    nothing retries a failed write. Under `rebac` the graph answers every
    check, so a failed revocation (a removed membership, application role,
    resource grant or platform admin) leaves the access in place while the
    database shows it revoked. `strict` reports the failure to the caller
    but keeps the database change. Use `strict` under `rebac`, monitor the
    failures, and repair the graph from the identity tables, as when
    switching modes below.

## Switching from `rbac` to `rebac`

A deployment that switches starts with an empty graph. Write the existing
memberships, application roles and grants through the syncer before serving
the first request; no bulk rebuild command ships yet.

## Errors

Configuration errors name the key and the accepted values and wrap
`systemauth.ErrInvalidConfig` when loaded through SystemAuth:

| Message | Cause |
|---|---|
| `authz: unknown mode "..." (want rbac or rebac)` | Mode misspelled |
| `authz: engine "..." is set but mode is rbac` | Engine given with `rbac` |
| `authz: spicedb settings are given but mode is rbac` | SpiceDB block with `rbac` |
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
