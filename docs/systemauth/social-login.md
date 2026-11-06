# Social Login (GitHub / Google)

SystemAuth can act as the single identity provider for "log in with GitHub /
Google". Upstream OAuth credentials live only in the SystemAuth deployment.
Relying-party applications do not implement social login themselves: they send
users to SystemAuth's `/oauth/authorize` as OIDC clients, and SystemAuth signs
the user in upstream when needed.

See ADR-002 (`docs/design/adrs/ADR-002-centralized-social-login-systemauth.md`)
for the design rationale.

## Routes

When `social_login` is configured, these routes are mounted next to the OAuth
endpoints:

| Route | Purpose |
|-------|---------|
| `GET /login?return_to=...` | The sign-in page: a link per provider, waiting for the person to choose, even with one provider. With `auto_select_single_provider`, redirects straight to the only provider. |
| `GET /login/{provider}?return_to=...` | Starts the upstream authorization-code flow (`github` or `google`). |
| `GET /account/sign-in-methods?return_to=...` | A signed-in person's page: their account's email, the sign-in methods linked to it, a button to link each other provider, and a link back to the validated `return_to` (see [Linking sign-in methods](#linking-sign-in-methods)). |
| `GET /login/{provider}/callback` | Upstream callback. Resolves the principal, sets the `__Host-sf_login` session, and redirects to `return_to`. |
| `GET /logout?return_to=...` | Renders a sign-out confirmation form (never signs out by itself). |
| `POST /logout` | Deletes the login session, clears the cookie, revokes all of the principal's access and refresh tokens, and redirects (`303`) to the validated `return_to` (default `default_redirect`). |
| `GET /consent?return_to=<authorize URL>` | Consent page naming the client and the requested scopes (for second- and third-party clients, or when the request sets `prompt=consent`). |
| `/login/verify-email...` | With [verification mail](verified-email.md): the pages that hold a sign-in whose provider email is unverified until a mailed link is opened in the same browser. |
| `/account/email...` | With [verification mail](verified-email.md): the signed-in person's email, and changing it after the new address is verified. |
| `POST /consent` | Records the decision. `allow` saves the grant and resumes `/oauth/authorize`; `deny` returns `error=access_denied` to the client's redirect URI. |

`/oauth/authorize` sends unauthenticated users to `/login?return_to=<authorize URL>`,
so after login the authorization request resumes and the relying party receives
an authorization code. No token ever appears in a redirect URL. An
`idp_hint=github|google` authorization parameter skips the chooser. When the
login was started by an authorization request, the chooser names the client
("to continue to ...") and shows its `logo_url`, an https URL, when it has
one. The authorization endpoint also honours the OIDC `prompt` parameter; see
[Silent sign-in and prompt](#silent-sign-in-and-prompt).

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

Whether a user is asked for consent depends on the client's **party**, who
owns the application (the customer owns the data in every case):

| Party | Who owns the app | Consent |
|-------|------------------|---------|
| `first_party` | The service provider running SystemAuth | Skipped |
| `second_party` | The customer | Asked and recorded |
| `third_party` | A partner | Asked and recorded |

A client declared in the configuration file is `first_party` unless it sets
`party`; a client registered at runtime (`RegisterClient`, storage, the
OAuth client store) without a party is `third_party`. Unknown values are
refused. See [SystemAuth](overview.md#client-party).

For a second- or third-party client, `/oauth/authorize` sends a signed-in user
to `/consent` the first time the client asks for a set of scopes. The page is
deliberately minimal (client name, scope descriptions, Allow/Deny). Decisions
are kept in a `ConsentStore`; with `EntStorage` the default is the database
(`sf_consent_grants`), otherwise in-memory (users are asked again after a
restart). See [Production Stores](production-stores.md). The consent form is protected by a CSRF token derived from the login
session, a same-origin check, and the
[security headers](deployment.md#security-headers) every page carries.

`skip_consent` is deprecated and ignored: it used to grant consent to every
client, including ones the operator does not own. SystemAuth logs a warning at
startup when it is set. First-party clients need no setting to skip consent.

### Silent sign-in and prompt

`/oauth/authorize` honours the OIDC `prompt` parameter
([OIDC Core 3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)):

| Value | Behaviour |
|-------|-----------|
| `none` | Shows no page. Without a login session the client gets `error=login_required`; when consent is needed (a second- or third-party client without recorded consent) `error=consent_required`; otherwise the request completes silently. Errors go to the client's redirect URI with its `state`. |
| `login` | Sends the user to the login page even with a login session. |
| `consent` | Shows the consent page even when consent is recorded, for first-party clients too: the client asked for it. |
| `select_account` | Accepted; it has no effect, since a browser has one login session. |

`none` combined with any other value, or an unknown value, answers
`error=invalid_request`. After the login or consent page, the authorization
request resumes without the prompt value that page satisfied. A first-party
application can therefore check for an existing SystemAuth session with
`prompt=none` (for example in a hidden redirect) and fall back to an
interactive sign-in on `login_required`. A relying party that needs a recent
login should also check the ID token's `auth_time`.

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
and token, so subjects, granted scopes and token families survive restarts
when `tokens.hmac_secret` is set ([Deploying SystemAuth](deployment.md#token-hmac-secret)).

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
  signup_minimum_age: 0
  insecure_cookies: false
```

| Field | Default | Notes |
|-------|---------|-------|
| `github`, `google` | disabled | `client_id` / `client_secret` support `${ENV}` expansion. `redirect_url` defaults to `{issuer}/login/{provider}/callback`; register that URL with the provider. |
| `allowed_redirect_origins` | none | Absolute origins a `return_to` may target in addition to the issuer origin. Relative same-origin paths are always allowed. |
| `default_redirect` | `/` | Used when no `return_to` is given. Must itself pass the allowlist. |
| `signed_out_url` | none | Where every sign-out lands, whatever `return_to` the app sent, such as the product's marketing site. Must pass the allowlist, so list its origin in `allowed_redirect_origins`. |
| `signed_out_name` | `signed_out_url`'s host | Display name of the site at `signed_out_url`, such as `ProductBuildersHQ`. The waitlist page links back to `signed_out_url` as "← Back to <name>". Display text only; the link always goes to `signed_out_url`. |
| `session_lifetime` | `12h` | Absolute lifetime of the login session. |
| `auto_select_single_provider` | `false` | With one provider, skip the sign-in page and go straight to it. Off by default: a browser that has just signed out would otherwise be signed straight back in, since the provider keeps its own session and remembers the person's authorization. |
| `skip_consent` | `false` | Deprecated and ignored; logs a warning at startup when set. First-party clients skip consent and other clients always ask (see [Consent](#consent)). |
| `signup_minimum_age` | `0` | Asks a person's birth month and year before their first login creates an account, and refuses anyone younger, keeping nothing. See [Deploying SystemAuth](deployment.md#minimum-sign-up-age). |
| `insecure_cookies` | `false` | Drops the `__Host-` prefix and `Secure` flag for local HTTP development, and logs a warning at startup. Never enable in production. See [Browser Cookies](../guides/cookies.md). |

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
2. **Authoritative-email linking fallback.** If the identity is not linked
   yet, an upstream email the provider is *authoritative* for links it to an
   existing principal whose own email is verified. Google is authoritative for
   `gmail.com` and `googlemail.com` addresses, and for a Workspace account's own
   domain (the `hd` claim). GitHub is never authoritative.
3. **Create.** Otherwise a new principal is created, which requires a verified
   upstream email.

An unverified upstream email never links to, or creates, an account. With
[verification mail](verified-email.md) configured, the sign-in is held
instead while SystemAuth mails a link to the address; a link opened in the
same browser proves the address, which then counts as verified and
authoritative. A
verified but not authoritative email never links either: a provider can keep
an address marked verified after its owner loses the mailbox. When such an
email already belongs to an account, the sign-in is refused as a conflict
(`ErrEmailConflict`), and the person signs in the way they signed in before.
GitHub sign-in uses the account's primary email only.

### Linking sign-in methods

A signed-in person can link another provider's sign-in to their account at
`/account/sign-in-methods`, so either one signs them in to the same account,
whatever email each provider reports. The page shows the account's email
and the providers already linked to it, and a **Link** button for each
configured provider that is not. The button's form posts to
`/account/sign-in-methods/{provider}`, which is origin-checked like sign-out
and needs a login session. It sends the browser through the provider's
sign-in. The callback then attaches that provider identity to the account:

- The browser must still be signed in as the account that started the link.
- An identity already on another account is never moved, and the page says
  so. Removing a sign-in method from an account, or merging two accounts, is
  not available yet: link a provider before its first sign-in makes an
  account of its own.
- An identity already on this account is a success that changes nothing.
- No account is created, no sign-up gate or age question applies, and the
  account's own email is unchanged.

An application links to the page from its own account settings with
`return_to`, such as
`https://auth.example.com/account/sign-in-methods?return_to=https://app.example.com/settings`.
`return_to` passes the same allowlist as sign-in's: a path on the issuer, or
an origin in `allowed_redirect_origins`. A valid one shows a **Back to**
link named by `signed_out_name`, or by its host when that is not set, and is
kept through signing in first, the link button, the provider and the
callback's return to the page; it is validated again at each step. An
invalid one is ignored: the page shows no back link and never redirects to
it.

A directory lists the linked providers through the optional
`LinkedProviderLister` interface, which the Ent and memory directories
implement. With a directory that does not, the page offers every provider.

A completed link, and a link the callback refuses (the identity is on
another account, or the browser is no longer signed in as the account that
started it), is the security event `systemauth.sign_in_method.linked`. A
start refused before the provider, such as a cross-origin request, is not;
nor is a denial at the provider, which is a refused sign-in
(`systemauth.sign_in`).

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
