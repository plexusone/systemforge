# Connections to External Services

Organizations connect accounts at services they already use, such as a CDN,
product analytics or monitoring, and applications use those connections
without ever holding the credential. SystemAuth stores the connections,
seals their credentials, tests them, and hands applications authenticated
HTTP clients. The design is [ADR-017](../design/adrs/ADR-017-external-connections.md);
the mechanism is [connectionforge](https://github.com/plexusone/connectionforge).

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
| `allow_private_egress` | Development only: lets provider requests reach loopback and private addresses over plain HTTP |

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
	connectionforge.Principal{Kind: connectionforge.PrincipalUser, ID: userID.String()},
	connectionID,
	connectionforge.Use{Consumer: connectionforge.Consumer{Kind: "application", ID: "dashboards"}, Purpose: "traffic"},
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
| `GET /api/v1/providers` | Provider manifests: methods, fields, scopes |
| `GET /api/v1/organizations/{org}/connections` | Connections the caller may view (`?provider=`, `?state=`) |
| `POST /api/v1/organizations/{org}/connections` | Connect: `{"provider", "authMethod", "displayName", "fields": {...}}` |
| `GET /api/v1/organizations/{org}/connections/{id}` | One connection |
| `PATCH /api/v1/organizations/{org}/connections/{id}` | Rename: `{"displayName"}` |
| `POST /api/v1/organizations/{org}/connections/{id}/test` | Validate again; the result is in `health` |
| `DELETE /api/v1/organizations/{org}/connections/{id}` | Disconnect and destroy the credential |

A connection is validated with its provider before it is stored, and a
rejected credential stores nothing (`422`). No response contains a
credential. A connection the caller may not view is reported as `404`.

## Who may do what

| Role | View | Use | Manage, share, disconnect |
|---|---|---|---|
| Organization owner, admin | Yes | Yes | Yes |
| Member | Yes | No | No |
| Collaborator | No | No | No |
| The connection's creator | Yes | Yes | Yes |

Creating a connection needs an owner or admin. Resource grants (ADR-008) on
type `systemforge_connection` will let a member or collaborator view
(`viewer`), use (`contributor`) or manage (`maintainer`) one connection; the
grants API for connections is not served yet.

## Credentials and keys

A connection's credential is sealed under keys that SystemAuth manages
through keyforge, using the `connections.keys_dir` and `connections.root_key`
settings above. Back up the keys directory with the database: without it,
stored credentials cannot be read. See [Key management](key-management.md).

## Current limits

- Static API tokens only; GitHub App and OAuth connections follow
  (connectionforge v0.1.0).
- The role-based authorization mode only.
- The API acts for the token's principal as a user; service principals and
  agents use the broker in process.
- Connection events go to the server log until an audit store is configured.
