# Connections to External Services

Organizations connect accounts at services they already use, such as a CDN,
product analytics or monitoring, and applications use those connections
without ever holding the credential. SystemAuth stores the connections,
seals their credentials, tests them, and hands applications authenticated
HTTP clients. The design is [ADR-017](../design/adrs/ADR-017-external-connections.md);
the mechanism is [connectforge](https://github.com/plexusone/connectforge).

## Enable connections

Add a `connections` section to the SystemAuth configuration. It needs a
database and the role-based authorization mode (the default).

```yaml
connections:
  keys_dir: /var/lib/systemauth/keys
  vault: env://
  root_key: SYSTEMAUTH_KEYS_ROOT
```

| Key | Meaning |
|---|---|
| `keys_dir` | Directory holding the key ring and its registry. Back it up with the database: without it, stored credentials cannot be read |
| `vault` | omnivault URI of the deployment's secret store: `env://`, `file:///etc/systemauth/secrets`, or a registered provider |
| `root_key` | Path in the vault of the key ring's root key: 32 random bytes as base64 or hex |
| `egress_allow_prefixes` | Development only: address ranges in CIDR notation, such as `127.0.0.0/8`, that provider requests may reach although they are not public. List only the ranges your local fakes use. Link-local and cloud metadata addresses are refused even when listed |
| `allow_http_egress` | Development only: lets provider requests use plain HTTP |

When either development setting is on, SystemAuth logs a warning at startup.

Create the root key once and keep it in the secret store, not beside
`keys_dir`:

```bash
export SYSTEMAUTH_KEYS_ROOT="$(openssl rand -base64 32)"
```

`systemauth migrate` (and `--migrate` at startup) creates the connection
tables. On PostgreSQL it also enables row-level security on them, keyed on
`owner_id`, the organization.

`systemauth serve` runs the key lifecycle jobs. A host that embeds SystemAuth
calls `Service.RunJobs` itself.

People manage connections in the [organization console](console.md),
which SystemAuth serves under `/console` when it is enabled.

## Register providers

Providers are registered by the application that embeds SystemAuth, through
`systemauthsvc.Options.Providers`. A static-token service needs only a
manifest and where its token goes:

```go
reg := provider.NewRegistry()
p, err := apikey.New(apikey.Config{
	Manifest: provider.Manifest{
		Key: "cloudflare", DisplayName: "Cloudflare",
		BaseURLs: []string{"https://api.cloudflare.com"},
		AuthMethods: []provider.AuthMethod{{
			Key:    "api_token",
			Fields: []provider.Field{{Name: "token", Label: "API token", Secret: true, Required: true}},
		}},
	},
	Verify: apikey.Request{Path: "/client/v4/user/tokens/verify"},
})
if err != nil {
	return err
}
if err := reg.Register(p); err != nil {
	return err
}
svc, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{Providers: reg})
```

Requests for a provider may reach only its manifest's `BaseURLs`, over
HTTPS, never a private address, and never by a redirect to another host.

## Use a connection in process

An application in the same process gets an authenticated client from the
broker and hands it to the provider's SDK:

```go
ctx = rls.ContextWithTenant(ctx, orgID) // row-level security on PostgreSQL
hc, err := svc.Connections().Broker.HTTPClient(ctx,
	connections.OwnerFor(orgID),
	connectforge.Principal{Kind: connectforge.PrincipalUser, ID: userID.String()},
	connectionID,
	connectforge.Use{Consumer: connectforge.Consumer{Kind: "application", ID: "dashboards"}, Purpose: "traffic"},
)
if err != nil {
	return err
}
client := providersdk.New(providersdk.WithHTTPClient(hc)) // any SDK that accepts an *http.Client
```

The broker checks that the principal may use the connection and that it is
connected. Make a client per unit of work: a disconnect applies to the next
client.

## HTTP API

Every request carries a SystemAuth access token. Reads need the
`systemforge:connections:read` scope; changes need
`systemforge:connections:write`.

| Method and path | Action |
|---|---|
| `GET /api/v1/providers` | Provider manifests: methods, fields, scopes, setup steps and rotation modes |
| `GET /api/v1/organizations/{org}/connections` | Connections the caller may view (`?provider=`, `?state=`) |
| `POST /api/v1/organizations/{org}/connections` | Connect: `{"provider", "authMethod", "displayName", "fields": {...}, "rotation"}`; `rotation` is optional |
| `GET /api/v1/organizations/{org}/connections/{id}` | One connection |
| `PATCH /api/v1/organizations/{org}/connections/{id}` | Rename: `{"displayName"}` |
| `POST /api/v1/organizations/{org}/connections/{id}/test` | Validate again; the result is in `health` |
| `POST /api/v1/organizations/{org}/connections/{id}/reconnect` | Replace the credential: `{"fields": {...}}` |
| `GET /api/v1/organizations/{org}/connections/{id}/bindings` | What depends on the connection |
| `PUT /api/v1/organizations/{org}/connections/{id}/bindings` | Record a dependency: `{"consumerKind", "consumerId", "purpose"}` |
| `DELETE /api/v1/organizations/{org}/connections/{id}/bindings?kind=&id=&purpose=` | Remove one |
| `GET /api/v1/organizations/{org}/connections/{id}/grants` | Who holds a role on the connection |
| `PUT /api/v1/organizations/{org}/connections/{id}/grants/{principal}` | Give a role: `{"role": "viewer" \| "contributor" \| "maintainer"}` |
| `DELETE /api/v1/organizations/{org}/connections/{id}/grants/{principal}` | Take it back |
| `DELETE /api/v1/organizations/{org}/connections/{id}` | Disconnect and destroy the credential |

A connection is validated with its provider before it is stored, and a
rejected credential stores nothing (`422`). No response contains a
credential. A connection the caller may not view is reported as `404`.

### Setup and rotation

Each auth method in a provider manifest may describe how to get the
credential and how it is replaced over its life:

- `setup` lists the steps a person takes at the service to create the
  credential, each with a `title` and optionally a `detail` and a `url`. A
  step with `rotation` applies only to those rotation modes.
- `rotation` lists the rotation modes the method offers, such as `manual`
  (a person replaces the credential) or `automatic`.

A connect may name one of the method's rotation modes in `rotation`. It is
kept in the connection's `metadata` under `rotation`, so a page can say how
the credential is replaced. A mode the method does not list is refused with
`400`. SystemAuth records the mode; it does not rotate credentials itself.

When the provider reports when the credential expires, the connection's
`health.credentialExpiresAt` carries it, recorded each time the credential
is validated: on connect, test and reconnect. Use it to
warn people before the credential stops working, and reconnect before then.

## Reconnecting

When a token expires or is revoked, replace it in place with `reconnect`. The
new credential is validated with the provider first and must belong to the
**same account**; otherwise nothing changes (`422`). Everything bound to the
connection keeps working.

## Who may do what

| Role | View | Use | Manage, share, disconnect |
|---|---|---|---|
| Organization owner, admin | Yes | Yes | Yes |
| Member | Yes | With a grant | With a grant |
| Collaborator | With a grant | With a grant | With a grant |
| The connection's creator | Yes | Yes | Yes |

Creating a connection needs an owner or admin. Grants are resource roles
(ADR-008) on type `systemforge_connection`:

| Role | Lets the principal |
|---|---|
| `viewer` | See the connection |
| `contributor` | Use it, and record what depends on it |
| `maintainer` | Manage it: rename, test, reconnect, share, disconnect |

Giving someone a role on a connection who is not in the organization makes
them a collaborator, with access to that connection only. Granting needs the
**share** action, which is `maintainer`, an owner or an admin.

Roles are never visible to the connection's provider; they decide who in your
organization may use the stored credential, not what the credential can do.

## Credentials and keys

A connection's credential is sealed under keys that SystemAuth manages
through keyforge, using the `connections.keys_dir` and `connections.root_key`
settings above. Back up the keys directory with the database: without it,
stored credentials cannot be read. See [Key management](key-management.md).

## Current limits

- Static API tokens only; GitHub App and OAuth connections follow.
- The role-based authorization mode only.
- The API acts for the token's principal as a user; service principals and
  agents use the broker in process.
- Connection events go to the server log unless the embedding host passes
  an audit store in `systemauthsvc.Options.AuditStore`; the `systemauth`
  command does not.
- A disconnect does not yet require acknowledging the bindings it would stop;
  list them first with `GET .../bindings`.
