# Social Login (GitHub / Google)

SystemAuth can act as the single identity provider for "log in with GitHub /
Google". Upstream OAuth credentials live only in the SystemAuth deployment.
Relying-party applications do not implement social login themselves: they send
users to SystemAuth's `/oauth/authorize` as OIDC clients, and SystemAuth signs
the user in upstream when needed.

See ADR-002 (`docs/specs/adrs/ADR-002-centralized-social-login-systemauth.md`)
for the design rationale.

## Routes

When `social_login` is configured, these routes are mounted next to the OAuth
endpoints:

| Route | Purpose |
|-------|---------|
| `GET /login?return_to=...` | Provider chooser. Redirects straight to the provider when only one is configured. |
| `GET /login/{provider}?return_to=...` | Starts the upstream authorization-code flow (`github` or `google`). |
| `GET /login/{provider}/callback` | Upstream callback. Resolves the principal, sets the `__Host-sf_login` session, and redirects to `return_to`. |
| `GET /logout?return_to=...` | Renders a sign-out confirmation form (never signs out by itself). |
| `POST /logout` | Deletes the login session, clears the cookie, revokes all of the principal's access and refresh tokens, and redirects (`303`) to the validated `return_to` (default `default_redirect`). |
| `GET /consent?return_to=<authorize URL>` | Consent page naming the client and the requested scopes (only when `skip_consent` is off). |
| `POST /consent` | Records the decision. `allow` saves the grant and resumes `/oauth/authorize`; `deny` returns `error=access_denied` to the client's redirect URI. |

`/oauth/authorize` sends unauthenticated users to `/login?return_to=<authorize URL>`,
so after login the authorization request resumes and the relying party receives
an authorization code. No token ever appears in a redirect URL. An
`idp_hint=github|google` authorization parameter skips the chooser.

Applications consume this through the `identity/relyingparty` package; see
[Relying Parties](relying-party.md).

### Logout

Relying parties sign the user out of SystemAuth by sending the browser to
`GET /logout?return_to=https://app.example.com/` (a confirmation page) or by
submitting a form `POST /logout` from their own origin. The `POST` must carry an
`Origin` (or `Referer`) of the issuer or one of `allowed_redirect_origins`;
anything else is rejected with `403`. Logout revokes every token issued to the
principal, for every client, through the storage's `SubjectTokenRevoker`
support (implemented by `MemoryStorage` and `EntStorage`).

### Consent

With `skip_consent: false`, `/oauth/authorize` sends a signed-in user to
`/consent` the first time a client asks for a set of scopes. The page is
deliberately minimal (client name, scope descriptions, Allow/Deny). Decisions
are kept in a `ConsentStore`; with `EntStorage` the default is the database
(`sf_consent_grants`), otherwise in-memory (users are asked again after a
restart). See [Production Stores](production-stores.md). The consent form is protected by a CSRF token derived from the login
session, a same-origin check, and `frame-ancestors 'none'`. Deployments whose
clients are all first-party should set `skip_consent: true` instead.

## Refresh tokens

SystemAuth issues refresh tokens to clients granted `offline_access` (and the
`refresh_token` grant). They are rotated on every use:

- Each refresh returns a **new** refresh token and retires the previous refresh
  and access tokens.
- **Reuse detection:** presenting a refresh token that was already rotated
  fails with `invalid_grant` and revokes the **entire token family** (every
  token descended from the original authorization), since either the client or
  an attacker holds a stolen copy.
- **Absolute expiry:** `tokens.refresh_token_absolute_lifetime` (default
  `720h`) caps a family's lifetime across rotations; after it the user must
  sign in again. It must be at least `tokens.refresh_token_lifetime`.

Persistent storage (`EntStorage`) keeps the full Fosite session with each code
and token, so subjects, granted scopes and token families survive restarts.

## Configuration

```yaml
issuer: https://auth.example.com

social_login:
  github:
    client_id: ${GITHUB_CLIENT_ID}
    client_secret: ${GITHUB_CLIENT_SECRET}
  google:
    client_id: ${GOOGLE_CLIENT_ID}
    client_secret: ${GOOGLE_CLIENT_SECRET}
  allowed_redirect_origins:
    - https://app.example.com
  default_redirect: /
  session_lifetime: 12h
  skip_consent: false
  insecure_cookies: false
```

| Field | Default | Notes |
|-------|---------|-------|
| `github`, `google` | disabled | `client_id` / `client_secret` support `${ENV}` expansion. `redirect_url` defaults to `{issuer}/login/{provider}/callback`; register that URL with the provider. |
| `allowed_redirect_origins` | none | Absolute origins a `return_to` may target in addition to the issuer origin. Relative same-origin paths are always allowed. |
| `default_redirect` | `/` | Used when no `return_to` is given. Must itself pass the allowlist. |
| `session_lifetime` | `12h` | Absolute lifetime of the login session. |
| `skip_consent` | `false` | Auto-grant consent for users signed in via social login. Only for deployments where every client is first-party; otherwise users see the `/consent` page. |
| `insecure_cookies` | `false` | Drops the `__Host-` prefix and `Secure` flag for local HTTP development. Never enable in production. |

Programmatic setup:

```go
server, err := systemauth.NewEmbedded(cfg,
    systemauth.WithStorage(systemauth.NewEntStorage(db)),
    // optional overrides:
    systemauth.WithPrincipalDirectory(systemauth.NewEntPrincipalDirectory(db)),
    systemauth.WithLoginSessionStore(mySharedSessionStore),
    systemauth.WithLoginStateStore(mySharedStateStore),
    systemauth.WithConsentStore(mySharedConsentStore),
)
```

With `EntStorage` the principal directory defaults to Ent; otherwise an
in-memory directory is used (development only).

## Account linking

Logins resolve to a `Principal` (type `human`, with its `Human` extension) —
never a legacy `User` row — using one model:

1. **Provider identity first.** The `(provider, subject)` pair (GitHub numeric
   user ID, Google `sub`) is stored in `sf_external_identities` and is the
   primary key. A returning user is matched by it even if their email changed.
2. **Verified-email linking fallback.** If the identity is not linked yet, a
   *verified* upstream email links it to an existing principal whose own email
   is verified.
3. **Create.** Otherwise a new principal is created, which requires a verified
   upstream email.

An unverified upstream email never links to, or creates, an account. An email
already held by an unverified local account is reported as a conflict instead
of being linked.

## Security properties

- `state` is stored server-side (single use, 10 minute TTL) **and** bound to the
  browser with a `__Host-sf_oauth_state` cookie, so a callback URL cannot be
  replayed into another browser (login CSRF).
- PKCE (`S256`) is used on the upstream exchange.
- `return_to` is validated against the allowlist at start and again before the
  final redirect; `//host`, backslash, userinfo, and foreign-origin targets are
  rejected.
- The session cookie `__Host-sf_login` is host-only, `Secure`, `HttpOnly`,
  `SameSite=Lax`, `Path=/`; the token is 256 bits of randomness and only its
  SHA-256 hash is stored. A new token is issued on every login and any
  previously presented session is deleted.
- Upstream access tokens are used once to read the profile and are not stored.
- Logout and consent `POST`s are origin-checked; the consent form also carries
  a session-bound CSRF token. Both pages send `X-Frame-Options: DENY`.

## Current limitations

- Without `EntStorage`, the state, session and consent stores default to
  in-memory: run a single instance or supply shared stores via
  `WithLoginStateStore` / `WithLoginSessionStore` / `WithConsentStore`. With
  `EntStorage` they default to the database
  ([Production Stores](production-stores.md)).
- Logout ends the SystemAuth session and revokes tokens, but relying parties
  are not notified (no front- or back-channel logout yet).
- New principals are not added to any organization automatically.
- Upstream providers are GitHub and Google only.
