# TRD — Managed Principals for Relying-Party Applications

**Initiative:** `INIT-SYSTEMFORGE-012`
**Design of record:** [ADR-005](../../../design/adrs/ADR-005-managed-principals-and-manager-relationships.md)

## Current State

- `managedprincipal.Service` holds the invariants, audit, and authorization
  of managed principals. `managedprincipal.NewHandler` serves create,
  managers, claims, invitations, release, delete, and login-token and
  session visibility behind `requestprincipal.Middleware`. It has no route to
  list a manager's principals or to issue a login token, and takes the OAuth
  client from the request body.
- `systemauth.Config` already carries `managed_principals` and the per-client
  `managed_principals` and `login_token_ttl` settings, and `systemauth.Server`
  serves `POST /login-token` when managed principals are enabled and it has a
  credential service, which Ent storage provides.
- `systemauthsvc` builds SystemAuth for hosts. It mounts the connections API
  with `Server.BearerPrincipal`, but builds no managed-principal service.

## Design

### 1. Bearer access with the client (`identity/systemauth`)

```go
type BearerGrant struct {
    PrincipalID uuid.UUID
    ClientID    string
    Scopes      []string
    TokenID     string
    ExpiresAt   time.Time
}

func (s *Server) BearerAccess(r *http.Request, scope string) (*BearerGrant, error)
func (s *Server) BearerAuthenticator(scope string) requestprincipal.Authenticator
```

`BearerAccess` is `BearerPrincipal` plus the client the token was issued to.
`BearerAuthenticator` adapts it to `requestprincipal`: no bearer token is
`ErrNoCredentials`; an invalid token is a 401 and an insufficient scope a 403,
each with the RFC 6750 challenge. The principal carries `Protocol` `oidc`,
the scopes, `Proof.Issuer` (this server), `Proof.TokenID`, and the client ID
in `Claims["client_id"]`. Tokens from other issuers never reach introspection
as valid.

### 2. Remote callers (`identity/managedprincipal`)

`NewHandler(svc, opts ...HandlerOption)`; existing callers are unchanged.

- `WithRequestClient(func(*http.Request) (string, bool))` puts the handler in
  relying-party mode. The OAuth client of create and login-token requests is
  the authenticated one; a body `client_id` that differs is a 400. Create
  accepts exactly one manager, the caller, so an application cannot place
  another person in management without their consent.
- `WithCodeRateLimit(ratelimit.Storage, ratelimit.Limit)` limits
  `/claims/redeem`, `/manager-invites/accept`, and `/manager-invites/decline`
  per calling principal; over the limit is a 429 with `Retry-After`.
- `RequestClientFromPrincipal` reads `Claims["client_id"]` from the request
  principal, the counterpart of `BearerAuthenticator`.

New routes:

| Route | Authorization |
|---|---|
| `GET /` | The caller's own active relationships; `?after=&limit=` pages by principal ID, at most 200 a page |
| `POST /{principalID}/login-tokens` | The caller is an active manager (as `Service.IssueLoginToken`); the client allows managed principals |

`Service.ListManagedBy(ctx, managerID, after, limit)` returns
`ManagedSummary{PrincipalID, DisplayName, Roles}` for active managed
principals the manager actively manages.

### 3. SystemAuth wiring (`identity/systemauthsvc`)

When `managed_principals.enabled` is set and the service has an Ent client:

- build `managedprincipal.NewService(client, server, WithAuditEmitter,
  WithLogger)` with `Options.AuditEmitter`;
- mount `NewHandler` at `/managed-principals` behind
  `requestprincipal.Middleware(server.BearerAuthenticator(managedprincipal.Scope))`
  with `WithRequestClient(managedprincipal.RequestClientFromPrincipal)` and
  `WithCodeRateLimit` over in-memory storage
  (`managedprincipal.DefaultCodeLimit`, 10 a minute), or
  `Options.ManagedPrincipalRates` when several instances serve it;
- expose `Service.ManagedPrincipals()` for a host in the same process.

`managedprincipal.Scope` is `systemforge:managed_principals`. Clients that
call the API list it in their allowed scopes.

### 4. Client (`identity/managedprincipal/mpclient`)

```go
func New(baseURL string, hc *http.Client) *Client
func (c *Client) Create(ctx, token string, in CreateInput) (uuid.UUID, error)
func (c *Client) List(ctx, token string, after uuid.UUID, limit int) ([]ManagedSummary, error)
func (c *Client) IssueLoginToken(ctx, token string, id uuid.UUID, in IssueLoginTokenInput) (*LoginToken, error)
// ListLoginTokens, RevokeLoginToken, ListSessions, RevokeSession, RevokeAll,
// ListManagers, RemoveManager, IssueClaim, RedeemClaim
```

`token` is the manager's access token. Errors: `ErrUnauthorized`,
`ErrForbidden`, `ErrNotFound`, `ErrInvalidCode`, `ErrConflict`,
`ErrRateLimited`, each wrapped in `*APIError{Status, Message}`.

## Testing Strategy

- `systemauth`: `BearerAccess` and `BearerAuthenticator` with a valid token,
  no token, an unknown token, and a missing scope.
- `managedprincipal`: relying-party mode refuses a mismatched client and a
  second manager; list pages and excludes inactive relationships; login-token
  issue refuses non-managers and disallowed clients; the code rate limit
  answers 429.
- `systemauthsvc`: with managed principals enabled, an access token with the
  scope creates a principal, issues a login token, and that token signs in
  through `POST /login-token`; without the scope the API answers 403; with
  managed principals off the routes are absent.
- `mpclient`: against the handler, every method and error mapping.
