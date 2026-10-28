# TRD — Service Accounts with Key-Pair Credentials

**Initiative:** `INIT-SYSTEMFORGE-010`

## Current State

- **Fosite.** SystemAuth composes Fosite (v0.49) with the authorization-code,
  client-credentials, refresh, introspection, revocation, PKCE and OpenID
  Connect factories. The RFC 7523 factory is not registered.
  - Fosite's `compose.RFC7523AssertionGrantFactory` needs storage
    implementing `rfc7523.RFC7523KeyStorage`.
  - Its methods are `GetPublicKey`, `GetPublicKeys` and
    `GetPublicKeyScopes`, each keyed by issuer, subject and key ID, plus
    `IsJWTUsed` and `MarkJWTUsedForTime`.
- **Service principals** are `Principal(type=service)` with a
  `ServicePrincipal` row (service type, description, `created_by`,
  `last_used_at`, `allowed_ips`). `principal.CreateService` makes one.
  `Principal.organization_id` and `allowed_scopes` exist.
- **Key-pair credentials** are `sf_credentials` rows of type `keypair`:
  - a globally unique `key_id`, `key_algorithm` and a PEM public key;
  - scopes, expiry, and active and revoked flags;
  - managed with `credential.CreateKeypair`, `GetKeypairByKeyID`,
    `ListKeypairs` and `Revoke`.
- **Used assertion IDs** go in `sf_client_assertion_jtis`, through
  `clientassertion.JTIStore`.
- **The `orgs` claim** is added to any access token whose subject parses as a
  principal ID (`addOrgsClaims`). `EntOrgsSource` reads active memberships in
  active organizations and `approle` effective roles.
- **DPoP.** Every token request must carry a DPoP proof unless the client
  holds the `allow_bearer_tokens` exception (`systemauth/dpop.go`), and
  tokens are bound to the proof's key.
- **Ending access.** `approle.Remove` and `principal.Deactivate` record access
  changes.
- **Apps.** `relyingparty`'s bearer path refuses a subject with no local
  principal: "unknown principal; sign in to the application first"
  (`middleware.go`).

## Design

### 1. Service accounts in an organization

`identity/serviceaccount` is a small service over the existing packages:

```go
type Service struct{ /* ent client, principal, credential, approle services */ }

func (s *Service) Create(ctx context.Context, in CreateInput) (*Account, error)
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]*Account, error)
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Account, error)
func (s *Service) Disable(ctx context.Context, id, by uuid.UUID) error
func (s *Service) Enable(ctx context.Context, id, by uuid.UUID) error
func (s *Service) Delete(ctx context.Context, id, by uuid.UUID) error

func (s *Service) AddKey(ctx context.Context, id uuid.UUID, in KeyInput) (*Key, error)
func (s *Service) ListKeys(ctx context.Context, id uuid.UUID) ([]*Key, error)
func (s *Service) RevokeKey(ctx context.Context, id uuid.UUID, keyID, reason string) error

func (s *Service) GrantRole(ctx context.Context, id uuid.UUID, application, role string, by uuid.UUID) error
func (s *Service) RemoveRole(ctx context.Context, id uuid.UUID, application string, by uuid.UUID) error
```

- **`Create`** does three things in one transaction:
  1. creates the service principal, with its `organization_id`, a
     generated identifier (`sa_` and 26 random characters, per ADR-015) and
     its allowed scopes;
  2. creates the `ServicePrincipal` row with `created_by`;
  3. creates an active membership with the role `service_account`.

  The organization must be active and not personal.
- **`AddKey`** takes a PEM public key, or generates a P-256 key pair and
  returns the private key once, never stored. It calls
  `credential.CreateKeypair` with the key ID, algorithm (`ES256`, `RS256`
  or `EdDSA`), scopes and expiry. RSA keys must be at least 2048 bits.
- **`Disable`, `Delete` and `RevokeKey`.** `Disable` calls
  `principal.Deactivate`, which records `Deactivated`. `Delete` deactivates,
  removes roles, the membership and keys, then deletes. `RevokeKey` revokes
  the key and, when it was usable, records `SessionsRevoked`. Tokens do not
  record the key that obtained them, so all of the account's current tokens
  stop at once in applications with a revocation cache, and a workload
  holding another key exchanges it for a new token.
- **`GrantRole` and `RemoveRole`** call `approle`, whose removal already
  records an access change.

### 2. Key storage adapter

A type in `identity/systemauth` implementing `RFC7523KeyStorage` over Ent:

- **`GetPublicKey(ctx, issuer, subject, keyID)`:**
  - looks up the key-pair credential by `key_id`, and requires it active,
    unrevoked and unexpired;
  - loads its principal, and requires type service, active,
    `identifier == subject`, and an active organization;
  - requires `issuer == subject`;
  - parses the PEM into a `jose.JSONWebKey` with the stored algorithm and
    key ID.

  Every failure returns `fosite.ErrNotFound`, so a caller cannot tell a
  missing key from a refused one.
- **`GetPublicKeys(ctx, issuer, subject)`:** the same principal checks,
  returning every usable key, for an assertion without a `kid`.
- **`GetPublicKeyScopes`:** the key's scopes intersected with the
  principal's `allowed_scopes`.
- **`IsJWTUsed` and `MarkJWTUsedForTime`:** delegate to
  `clientassertion.JTIStore`.

### 3. Composition and configuration

```yaml
oauth:
  jwt_bearer:
    enabled: false
    max_assertion_lifetime: 5m
    token_lifetime: 15m
```

- **The factory.** `compose.RFC7523AssertionGrantFactory` is registered when
  enabled.
- **Required claims.** `jti` and `iat` are required: Fosite's ID-optional and
  issued-date-optional settings are off.
- **Client authentication.** The grant may skip it
  (`GrantTypeJWTBearerCanSkipClientAuth`), and the token is issued without a
  client.
- **Audience.** The accepted audience is the token endpoint URL or the
  issuer.
- **Discovery** adds the grant type to `grant_types_supported` when enabled.
- **DPoP.** A token request with this grant type and no DPoP proof is refused
  with `invalid_dpop_proof`, before client rules are considered, so no
  exception can apply.

### 4. Issued tokens

- **Subject** is the service principal's ID, so `addOrgsClaims` adds the
  account's one organization with its application roles.
- **The `principal_type: "service"` claim** is added for a service
  principal's tokens, as `managed` is for managed principals.
- **No refresh token.** Lifetime is `token_lifetime`.
- **On success,** the credential's `last_used_at` and `last_used_ip` and the
  service principal's `last_used_at` are updated.
- **Storage.** Tokens use the existing token storage, so introspection and
  revocation work unchanged.

### 5. Commands

`identity/serviceaccount/serviceaccountcmd` provides `service-account` as a
cobra command a host CLI mounts, with the same `Open` function as
`signupgate/signupcmd`. It opens the identity database directly, so it works
whether or not the server is running and never changes the schema.
`cmd/systemauth` registers it, and a host that embeds SystemAuth mounts it in
its own server binary. Each subcommand writes JSON with `--json`.

```text
systemauth service-account create --org <slug> --name <name> [--scope ...]
systemauth service-account list --org <slug>
systemauth service-account show <id>
systemauth service-account disable|enable|delete <id>
systemauth service-account key add <id> --out key.pem [--expires-in 2160h] [--scope ...]
systemauth service-account key add <id> --public-key pub.pem
systemauth service-account key list <id>
systemauth service-account key revoke <id> <key-id>
systemauth service-account role grant <id> --app <app> --role <role>
systemauth service-account role remove <id> --app <app>
```

- **`key add --out`** writes the private key with mode `0600`, refuses to
  overwrite a file, and prints the account identifier, key ID and issuer the
  client needs.
- **Audit.** `--by` names the operator's principal ID for the `created_by`
  and `assigned_by` fields, as the `admin` commands do.

### 6. Client: `identity/serviceclient`

```go
type Config struct {
	Issuer     string        // SystemAuth's issuer
	Account    string        // the account identifier (iss and sub)
	KeyID      string
	PrivateKey crypto.Signer // ES256, RS256 or EdDSA
	Scopes     []string
	HTTPClient *http.Client
	Metadata   *relyingparty.Metadata
}

func New(ctx context.Context, cfg Config) (*Client, error)
func LoadPrivateKey(path string) (crypto.Signer, error) // PEM, owner-only file
func (c *Client) Token(ctx context.Context) (string, error)
func (c *Client) Transport(base http.RoundTripper) http.RoundTripper
func (c *Client) HTTPClient() *http.Client
```

- **The assertion:**
  - `iss` and `sub` are `Account`, `aud` is the token endpoint;
  - `iat` is now and `exp` is now plus 60 seconds;
  - `jti` is 128 random bits;
  - the header carries `kid`.
- **DPoP proofs** use the assertion key when it is P-256. For an RSA or
  Ed25519 assertion key, the client makes a P-256 key for proofs at `New`,
  since proofs are ES256; tokens are then bound to that key for the life of
  the process, which suits tokens without refresh.
- **Tokens.** The token is cached and renewed a minute before expiry, under a
  mutex, so concurrent requests share one exchange.
- **`Transport`** sets `Authorization: DPoP` with a proof for each request.
  It retries once on `use_dpop_nonce` when the body can be sent again, and
  once on `invalid_token` after renewing.

### 7. Applications

`relyingparty.BearerConfig` gains `ServicePrincipals bool`.

- **With it,** a verified access token whose subject has no local principal
  and whose `principal_type` claim is `service` creates one. It calls
  `PrincipalStore.CreatePrincipal` with a `VerifiedIdentity` whose `Service`
  field is true, and whose `Subject` and `Name` come from the token.
- **Without it,** the request is refused as today.
- **The store contract.** `PrincipalStore.CreatePrincipal`'s documentation
  adds that an identity with `Service` set is created with type `service`
  and no email. Stores that do not support it return an error, so an
  application must update its store before enabling the option.
- **The request then authenticates** as usual: `Type` is `service`, and
  memberships come from the `orgs` claim.

`appauth.Options` gains `ServiceAccounts bool`, passed through, and
`pgstore.PrincipalStore` supports service identities.

### 8. ADR-016

ADR-016 changes in two places:

- **Decision 2, automation holding a key pair:** "JWT-bearer grant with a
  self-issued assertion (RFC 7523 section 2.1), DPoP-bound". It previously
  said client credentials with `private_key_jwt`.
- **Decision 4** is marked implemented by this initiative.

## Testing Strategy

- **The service:**
  - create, in a personal organization (refused), and in an inactive one;
  - keys of each algorithm, short RSA keys refused;
  - revoke a key while another remains, and the last key;
  - disable, enable and delete, each with the access change recorded;
  - roles.
- **The adapter:**
  - unknown, revoked, expired or inactive key;
  - wrong principal type, inactive principal or organization;
  - subject or issuer mismatch;
  - scope intersection;
  - the JTI delegation.
- **End to end,** against an embedded SystemAuth:
  - P-256 and RSA keys get tokens that introspect with the account as
    subject, `cnf.jkt`, the `orgs` claim and `principal_type`;
  - refused: replay, an expired assertion, an overlong lifetime, a missing
    `jti`, the wrong audience, a missing DPoP proof and a disabled account.
- **Commands,** run against a test database: `key add --out` file mode and
  refusal to overwrite.
- **The client:**
  - renewal before expiry;
  - concurrent requests share one exchange;
  - the nonce retry;
  - an RSA assertion key with a P-256 proof key.
- **Applications.** An `appauth` application with `ServiceAccounts` accepts
  the account, sees its role, and creates its local principal once. After
  the role is removed, the account still authenticates but its memberships
  no longer include the organization, so the application's authorization
  refuses what needed the role. Without the option it refuses the token.
- **Discovery** follows the enabled flag.

## Risks

- **Key ownership.** Fosite looks keys up by issuer and subject. The
  adapter enforces that the key belongs to the subject, and this is tested
  directly.
- **PEM formats.** Parsing stored keys must accept what `CreateKeypair`
  writes; tests round-trip keys created through the service.
- **A store without service support** would fail creation at the first
  token. The option is off by default, and its documentation says to update
  the store first.
