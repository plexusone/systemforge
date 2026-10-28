# Service Accounts

A service account is automation that calls an API with no person present: a
CI job that publishes on merge, a scheduled import, an agent running on a
server. It belongs to one organization, holds application roles there like
a member, and authenticates with a private key it never shares. It signs a
short assertion, and SystemAuth issues it a short-lived DPoP-bound access
token through the JWT-bearer grant (RFC 7523 section 2.1). SystemAuth stores
only public keys.

Its tokens are like a person's to an application: their subject is the
account's principal ID, and they carry the `orgs` claim with its one
organization and its application roles. Access ends the usual ways, each
recorded as an access change: removing a role, disabling or deleting the
account, or revoking a key. Removing a role takes the organization out of
the account's memberships; the account still authenticates, and the
application's own authorization refuses what needed the role.

A person at a terminal uses [`identity/publicclient`](../guides/dpop-clients.md)
instead, signing in with their own account.

## 1. Enable the grant

The grant is off by default. Turn it on in SystemAuth's configuration:

```yaml
oauth:
  jwt_bearer:
    enabled: true
    max_assertion_lifetime: 5m   # the longest assertion accepted
    token_lifetime: 15m          # the access token's lifetime; no refresh token
```

Discovery then lists `urn:ietf:params:oauth:grant-type:jwt-bearer` in
`grant_types_supported`. SystemAuth issues these tokens under its reserved
client `systemauth-jwt-bearer`, which nothing can authenticate as.

## 2. Create the account

Operators manage accounts with the `service-account` command, which
`systemauth` provides and a host that embeds SystemAuth mounts in its own
binary (`identity/serviceaccount/serviceaccountcmd`). It opens the database
directly.

The standalone `systemauth` binary hosts no applications, so it knows no
application roles: `role grant` works only in a host binary that mounts the
command with its role vocabularies
(`serviceaccountcmd.DefaultService(registry)`). The examples below use
`notes-server`, a host that serves the `billing` application.

```bash
notes-server service-account create --org acme --name ci-publisher --scope invoices
# created sa_01jbk2... (7d3f...) in acme

notes-server service-account role grant sa_01jbk2... --app billing --role viewer

notes-server service-account key add sa_01jbk2... --out ci-publisher.pem
# added key 2Yk... (ES256) to sa_01jbk2...
# private key: ci-publisher.pem (keep it secret; it is not stored anywhere else)
#
# The workload needs:
#   issuer:  https://auth.example.com
#   account: sa_01jbk2...
#   key ID:  2Yk...
```

`key add --out` generates a P-256 key pair and writes the private key to a
new file that only its owner can read. To keep the private key on the
workload's machine, generate it there and register only the public key:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out key.pem
openssl pkey -in key.pem -pubout -out pub.pem
notes-server service-account key add sa_01jbk2... --public-key pub.pem
```

ES256 (P-256), RS256 (RSA with 2048 bits or more) and EdDSA (Ed25519) keys
are accepted. `--expires-in` limits a key's life, and `key list` shows when
each key was last used.

| Command | Does |
| --- | --- |
| `create --org <slug> --name <name>` | Create an account with a `service_account` membership in the organization |
| `list --org <slug>`, `show <account>` | List accounts; show one with its keys |
| `disable`, `enable`, `delete <account>` | Disabling stops new tokens and records an access change; deleting removes keys, roles and membership |
| `key add`, `key list`, `key revoke <account> <key-id>` | Manage keys; revoking a key ends the account's current tokens in applications with a revocation cache, and a workload holding another key gets a new one |
| `role grant --app --role`, `role remove --app` | Application roles in the account's organization |

Each accepts `--json`.

## 3. Call the API from the workload

In Go, `identity/serviceclient` does the rest: it signs assertions, requests
DPoP-bound tokens, renews them a minute before they expire, and adds a DPoP
proof to every request.

```go
key, err := serviceclient.LoadPrivateKey("ci-publisher.pem") // refuses a file others can read
if err != nil {
	return err
}
c, err := serviceclient.New(ctx, serviceclient.Config{
	Issuer:     "https://auth.example.com",
	Account:    "sa_01jbk2...",
	KeyID:      "2Yk...",
	PrivateKey: key,
})
if err != nil {
	return err
}
resp, err := c.HTTPClient().Get("https://billing.example.com/api/invoices")
```

A client in another language follows the same protocol:

1. Sign a JWT with the private key: header `kid` set to the key ID; claims
   `iss` and `sub` set to the account identifier, `aud` set to the token
   endpoint, `iat`, `exp` at most `max_assertion_lifetime` later, and a
   unique `jti`.
2. `POST` it to the token endpoint as
   `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=<jwt>`,
   with a DPoP proof in the `DPoP` header. A request without a proof is
   refused. Answer `use_dpop_nonce` by retrying with the nonce.
3. Call the API with `Authorization: DPoP <token>` and a new proof by the
   same key. When the token expires, sign a new assertion; there is no
   refresh token.

## 4. Accept service accounts in the application

An application built on [`identity/appauth`](../guides/app-authentication.md)
accepts service accounts with one option:

```go
auth, err := appauth.New(ctx, cfg, appauth.Options{
	Principals:      stores.Principals,
	Sessions:        stores.Sessions,
	LoginStates:     stores.LoginStates,
	Application:     "billing",
	ServiceAccounts: true,
})
```

The application then accepts tokens from `systemauth-jwt-bearer`, and an
account's first request creates its local principal, of type `service`,
since a service account never signs in. Requests arrive like any other: the
principal's `Type` is `service`, and its memberships come from the `orgs`
claim.

Without `appauth`, set `relyingparty.BearerConfig.ServicePrincipals` and list
`relyingparty.ServiceAccountClientID` in the client's `AcceptedClientIDs`.
The principal store must create service identities
(`VerifiedIdentity.Service`), as the in-memory and Postgres stores do.

## Refusals

The token endpoint refuses, with an RFC 6749 error that does not say which
check failed:

- an unknown, revoked, expired or inactive key, or one belonging to another
  account;
- an assertion whose `iss` or `sub` is not the key's account, whose audience
  is not the token endpoint or issuer, without `jti` or `iat`, valid for
  longer than `max_assertion_lifetime`, signed with another algorithm than
  the key's, or replayed;
- a request without a DPoP proof;
- a disabled account, or one whose organization is inactive.

## In code

The commands are a thin layer over `identity/serviceaccount`:

```go
svc, err := serviceaccount.New(serviceaccount.Config{
	Client:     client,
	Principals: principal.NewService(client),
	Roles:      approle.NewService(client, vocabularies),
})
acct, err := svc.Create(ctx, serviceaccount.CreateInput{OrganizationID: orgID, Name: "ci-publisher"})
err = svc.GrantRole(ctx, acct.ID, "billing", "viewer", operatorID)
key, err := svc.AddKey(ctx, acct.ID, serviceaccount.KeyInput{}) // key.PrivateKeyPEM, returned once
```

Accounts are service principals (`Principal(type=service)` with a
`ServicePrincipal` row), and keys are key-pair credentials in
`sf_credentials`; [ADR-016](../design/adrs/ADR-016-no-static-api-keys.md)
explains why automation uses them instead of static API keys.
