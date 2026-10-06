# Relying Parties (Federating to SystemAuth)

Applications do not implement GitHub/Google login themselves. They federate to
SystemAuth as OpenID Connect clients with the `identity/relyingparty` package,
which provides the whole browser and API surface:

| Piece | What it does |
|-------|--------------|
| `Client` | Discovery, authorization URL (state + nonce + S256 PKCE), code exchange, ID-token verification against the SystemAuth JWKS, UserInfo, refresh, revocation |
| `ResolvePrincipal` + `PrincipalStore` | Find-or-create the app-local principal keyed by the OIDC `sub` → `sf_principal_id`, with a verified-email linking fallback |
| `BFF` | `http.Handler` for the `/bff/*` cookie-session surface the shared frontend auth package expects |
| `BearerMiddleware` | Authenticates programmatic clients (CLI, MCP, services) with SystemAuth JWT access tokens or API keys |

See ADR-002 (`docs/specs/adrs/ADR-002-centralized-social-login-systemauth.md`)
for the design.

## SystemAuth setup

Register the application as a client and enable JWT access tokens if
programmatic clients will call the application with SystemAuth tokens:

```yaml
features:
  require_pkce: true
  enable_jwt_access_tokens: true   # needed by BearerMiddleware
clients:
  - id: my-app
    type: public                   # or confidential with a secret
    name: My App
    redirect_uris:
      - https://app.example.com/bff/auth/callback
    grant_types: [authorization_code, refresh_token]
    response_types: [code]
    scopes: [openid, profile, email, offline_access]
social_login:
  allowed_redirect_origins:
    - https://app.example.com
```

SystemAuth returns an RS256 `id_token` (with `nonce`, `auth_time`, and the
scope-filtered `email`, `email_verified`, `name`, `picture`), rotating refresh
tokens, and serves `/oauth/userinfo`. Every JWT carries the `kid` published in
`/.well-known/jwks.json`.

## Application setup

```go
import "github.com/plexusone/systemforge/identity/relyingparty"

client, err := relyingparty.NewClient(ctx, relyingparty.Config{
    Issuer:      "https://auth.example.com",
    ClientID:    "my-app",
    RedirectURL: "https://app.example.com/bff/auth/callback",
    // ClientSecret: os.Getenv("SYSTEMAUTH_CLIENT_SECRET"), // confidential clients
})
if err != nil {
    return err
}

principals := myapp.NewPrincipalStore(db) // implements relyingparty.PrincipalStore

bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{
    Client:     client,
    Principals: principals,
    Sessions:   mySharedSessionStore, // default: in-memory (single instance)
})
if err != nil {
    return err
}

r := chi.NewRouter()
r.Mount("/bff", bff)

// Browser-only routes: BFF session required.
r.With(bff.RequireSession).Get("/app/api/projects", listProjects)

// API used by browsers and programmatic clients alike.
r.Route("/api/v1", func(r chi.Router) {
    r.Use(relyingparty.BearerMiddleware(relyingparty.BearerConfig{
        Tokens:     client,         // SystemAuth JWT access tokens
        APIKeys:    apiKeyService,  // *apikey.Service
        Principals: principals,
        Sessions:   bff,            // also accept the BFF cookie
    }))
    r.Get("/projects", listProjects)
})

func listProjects(w http.ResponseWriter, r *http.Request) {
    p, _ := relyingparty.PrincipalFromContext(r.Context())
    // p.ID, p.Type, p.Subject, p.Method, p.Scopes, p.Memberships
}
```

## `/bff/*` contract

The routes match the shared frontend auth package (`BFFClient`):

| Route | Response |
|-------|----------|
| `GET /bff/session` | `200 {"authenticated": false}` or `{"authenticated": true, "user_id", "expires_at", "user": User}` |
| `GET /bff/api/v1/users/me` | `200 User` or `401 {"code": "UNAUTHENTICATED", "message"}` |
| `GET /bff/auth/login?return_to=` | `302` to SystemAuth `/oauth/authorize` |
| `GET /bff/auth/{github,google}?return_to=` | Same, with `idp_hint` so SystemAuth skips its provider chooser |
| `GET /bff/auth/callback` | Verifies the login, creates the session, `302` to `return_to` |
| `POST /bff/auth/logout` | Deletes the session, revokes the SystemAuth refresh token, `204` |
| `POST /bff/auth/login` | `501 PASSWORD_LOGIN_UNSUPPORTED` (password login is not offered) |

`User` is `{id, email, name, avatar_url?, memberships: [{id, organization_id,
organization_name, organization_slug, role, joined_at}], created_at,
updated_at?}`. Errors are `{code, message}`.

Security properties:

- The session cookie (`__Host-sf_rp_session`) is an opaque 256-bit token,
  `Secure`, `HttpOnly`, `SameSite=Lax`, host-only; only its SHA-256 hash is
  stored. SystemAuth tokens never reach the browser. A new token is issued on
  every login and any presented session is deleted (no fixation).
- Login state is single-use, server-side, and bound to the browser with a
  `__Host-sf_rp_state` cookie; PKCE and the OIDC `nonce` are always used.
- The ID token is verified per OIDC Core §3.1.3.7 (RS256 signature against
  the JWKS, `iss`, `aud`/`azp`, `exp`, `nonce`), and the UserInfo `sub` must
  match it.
- `return_to` must be a same-origin path or an absolute URL on the app origin
  or `AllowedOrigins`.
- `POST /bff/auth/logout` and unsafe methods behind `RequireSession` require a
  JSON body and, when the browser sends one, an allowed `Origin`.

`BFF.AccessToken(r)` returns a SystemAuth access token for the session,
refreshing it when it is about to expire and storing the rotated refresh
token; a rejected refresh (revoked, reused, or past
`refresh_token_absolute_lifetime`) ends the session.

Logging out of the app does not end the SystemAuth login session. To sign the
user out everywhere, send the browser to SystemAuth `GET /logout?return_to=...`
after `POST /bff/auth/logout`.

## Account linking

`ResolvePrincipal` applies the same rules as SystemAuth:

1. The `sub` (SystemAuth principal ID), stored as `sf_principal_id`, is the
   primary key: a linked principal signs in even if its email changed.
2. Otherwise a **verified** identity email links to an existing principal whose
   own email is verified and that is not linked to another SystemAuth
   principal.
3. Otherwise a principal is created, which requires a verified email.

An unverified email never links to or creates a principal; an email held by an
unverified (or differently linked) local principal is a conflict (`409
ACCOUNT_CONFLICT`).

## Implementing `PrincipalStore`

The package is storage-agnostic. An application with its own Ent schema
implements `PrincipalStore` over it; a principal entity using
`identity/ent/mixin.PrincipalMixin` already has the unique, indexed
`sf_principal_id` field:

```go
type entPrincipals struct{ db *ent.Client }

func (s entPrincipals) FindBySubject(ctx context.Context, sub string) (*relyingparty.Principal, error) {
    id, err := uuid.Parse(sub)
    if err != nil {
        return nil, relyingparty.ErrPrincipalNotFound
    }
    p, err := s.db.Principal.Query().Where(principal.SfPrincipalIDEQ(id)).Only(ctx)
    if ent.IsNotFound(err) {
        return nil, relyingparty.ErrPrincipalNotFound
    }
    if err != nil {
        return nil, err
    }
    return toRP(p), nil
}

// LinkSubject: UPDATE ... SET sf_principal_id = ? WHERE id = ?; map the unique
// violation to relyingparty.ErrSubjectLinked. CreatePrincipal: insert with
// sf_principal_id and a verified email; map unique violations to
// ErrSubjectLinked / ErrEmailConflict.
```

`MemoryPrincipalStore` is provided for development and tests.

## Programmatic clients

`BearerMiddleware` accepts, in order:

- `Authorization: Bearer <JWT>` — a SystemAuth JWT access token, verified
  against the JWKS (`iss`, `exp`, and `Config.AccessTokenAudience` when set).
  Its `sub` must already be linked to a local principal (the user signed in to
  the app once). Client-credentials tokens (`sub` = `client_id`) are accepted
  as a `client` principal only with `AllowClientTokens`.
- `Authorization: Bearer <api key>` or `X-API-Key` — validated by an
  `APIKeyValidator` (`*apikey.Service`); the key's owner is the principal and
  an organization-scoped key only carries that organization's membership.
- The BFF session cookie, when `Sessions` is set.

Failures return `401` with `WWW-Authenticate: Bearer realm="api"` (plus
`error="invalid_token"` for bad credentials).

## Limitations

- JWT access tokens are verified statelessly: a revoked token stays usable
  until it expires (default 15 minutes). Opaque SystemAuth access tokens are
  not accepted by `BearerMiddleware` (no introspection client yet).
- The default session and login-state stores are in-memory; supply shared
  implementations for multiple replicas.
- No front- or back-channel logout notifications from SystemAuth.
