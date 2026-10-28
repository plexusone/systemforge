# TRD — Application Authentication

**Initiative:** `INIT-SYSTEMFORGE-014`

## Package

`identity/appauth` assembles `identity/relyingparty` for one application. It
depends on `relyingparty`, `relyingparty/pgstore`, `requestprincipal`,
`appcatalog` and `session/middleware`, and nothing depends on it.

```text
appauth.New(ctx, Config, Options)
  ├── relyingparty.Client     (metadata or discovery, the DPoP key)
  ├── relyingparty.BFF        (/bff/*, sessions, login states, app catalog)
  ├── MembershipSource        (claims or remote, filtered to the app's roles)
  └── request authentication  (session, DPoP token, optional API key,
                               then any extra authenticators)
```

## Configuration

```go
type Config struct {
	Issuer              string   // SystemAuth's issuer URL
	ClientID            string
	ClientSecret        string   // empty for a public client
	PublicURL           string   // origin the app is reached at
	AllowedOrigins      []string // other origins allowed to call the BFF
	AccessTokenAudience string
	AcceptedClientIDs   []string // other clients whose tokens the API accepts
	Scopes              []string // added to relyingparty.DefaultScopes
	DPoPKey             string   // PEM P-256 private key
	DPoPKeyFile         string   // or a file holding it
	BasePath            string   // default "/bff"
}

func (c Config) Configured() bool  // any field set
func (c Config) Validate(l Labels) error
func (c Config) RedirectURL() string // PublicURL + BasePath + "/auth/callback"

type Labels struct {
	Issuer, ClientID, ClientSecret, PublicURL, AllowedOrigins,
	AccessTokenAudience, AcceptedClientIDs, DPoPKey, DPoPKeyFile string
}

var DefaultLabels Labels

func ConfigFromEnv(prefix string) (Config, Labels)
```

- `ConfigFromEnv("APP")` reads the following variables:
  - `APP_SYSTEMAUTH_ISSUER`
  - `APP_CLIENT_ID`, `APP_CLIENT_SECRET`
  - `APP_PUBLIC_URL`, `APP_ALLOWED_ORIGINS` (comma-separated)
  - `APP_ACCESS_TOKEN_AUDIENCE`, `APP_ACCEPTED_CLIENT_IDS`
  - `APP_DPOP_KEY`, `APP_DPOP_KEY_FILE`

  It returns labels in the form `Issuer (APP_SYSTEMAUTH_ISSUER)`. A host
  relabels them by replacing the parenthesized part.
- `Validate` joins every problem with `errors.Join`, each starting with its
  label:
  - `%s is required`
  - `%s must be an absolute URL, got %q`
  - `%s must use https (http is allowed only for a loopback host), got %q`
  - `%s must be an origin without a path, got %q`
  - `%s and %s are both set`, for the key and the key file
  - `%s is required (generate one with %s)`
  - `%s: <parse error>`
- `PublicURL` and every allowed origin are origins: a scheme, a host and an
  optional port, with no path.
- `AcceptedClientIDs`, when set, always includes `ClientID`, so listing
  another client never stops the application accepting its own tokens.

## The DPoP Key

```go
const DPoPKeyCommand = "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256"

func ParseDPoPKey(pem string) (*dpop.KeyPair, error)
func ReadDPoPKeyFile(path string) (*dpop.KeyPair, error)
```

- **Accepted keys:** PKCS #8 or SEC 1 PEM, P-256 only. The errors are "not a
  PEM private key", "PEM block %q is not a private key", "parsing private
  key: …" and "must be a P-256 (ES256) key".
- **Required by default.** `Options.EphemeralDPoPKey` lets an application
  start without one. The client then generates a key per process, and `New`
  logs a warning that names the setting, the consequence (people sign in
  again after a restart) and `DPoPKeyCommand`.
- **A file for hosts.** A key file suits a deploy that writes secrets into a
  one-line-per-value environment file, which a multi-line PEM does not fit.
- **Tests** check a fixed key's RFC 7638 thumbprint against
  `Client.DPoPThumbprint()`, so a key that is parsed but not used fails.

## Options

```go
type Options struct {
	Principals  relyingparty.PrincipalStore  // required
	Sessions    relyingparty.SessionStore    // required unless PublicURL is loopback
	LoginStates relyingparty.LoginStateStore // required unless PublicURL is loopback

	Application string            // the app's key in an organization's applications
	KnownRole   func(string) bool // roles of Application this app accepts
	Memberships relyingparty.MembershipSource // replaces the default source

	Apps     appcatalog.Source  // for the product switcher
	Metadata *relyingparty.Metadata // SystemAuth's metadata, when embedded
	HTTPClient *http.Client

	EphemeralDPoPKey  bool
	ServiceAccounts   bool                       // accept service-account tokens (INIT-SYSTEMFORGE-010)
	AllowBearerTokens bool                       // unbound tokens, with a warning
	APIKeys           relyingparty.APIKeyValidator // Deprecated: nil, no API keys
	ReplayCache       relyingparty.DPoPReplayCache // default: in memory
	Revocation        *relyingparty.RevocationCache
	Authenticators    []requestprincipal.Authenticator // tried after the built-in ones

	ResourceName string // set to serve RFC 9728 metadata
	Logger       *slog.Logger
}
```

- **Memberships.** The default source is
  `ClaimsOrRemoteMemberships(RemoteMemberships(client))`. When `Application`
  is set, it keeps an organization only when
  `KnownRole(m.Applications[Application])` is true (any role when
  `KnownRole` is nil). An application that keeps its own membership tables
  passes `relyingparty.LocalMemberships(lister)` as `Memberships`.
- **Stores.** Without `Sessions` or `LoginStates`, `New` uses the in-memory
  stores only for a loopback `PublicURL`, and logs that sessions end at a
  restart. Otherwise it refuses.
- **Metadata.** With `Metadata`, the client is built without discovery after
  checking that its issuer equals `Config.Issuer` and that its authorization,
  token and keys endpoints are set.
- **API keys** are deprecated from the start. The field's doc comment
  carries `Deprecated:`, so linters flag new uses. `New` logs a warning naming
  `identity/publicclient` for command-line tools and service accounts for
  automation. It is removed in a later release, once applications have moved.
- **Replay cache.** The in-memory cache is per instance. Instances that share
  an API need a shared cache, which the option accepts.
- **Insecure cookies** are on exactly when `PublicURL` is `http` on a
  loopback host.

## Authenticator

```go
func New(ctx context.Context, cfg Config, opts Options) (*Authenticator, error)

func (a *Authenticator) Handler() http.Handler            // mount at BasePath
func (a *Authenticator) Middleware(required bool) func(http.Handler) http.Handler
func (a *Authenticator) RequestAuthenticator() requestprincipal.Authenticator
func (a *Authenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error)
func (a *Authenticator) Challenge(h http.Header)
func (a *Authenticator) Client() *relyingparty.Client
func (a *Authenticator) BFF() *relyingparty.BFF
func (a *Authenticator) SessionToken(r *http.Request) (string, error)
func (a *Authenticator) Transport(base http.RoundTripper) http.RoundTripper
func (a *Authenticator) ResourceMetadataHandler() http.Handler

var (
	ErrUnauthenticated = errors.New("appauth: unauthenticated")
	ErrForbidden       = errors.New("appauth: forbidden")
	ErrNoSessionToken  = errors.New("appauth: the request has no session token")
)
```

### Authenticating a request

The order is:

1. **An `Authorization` header** (`DPoP`, or `Bearer` for an API key or an
   allowed unbound token), verified by `relyingparty.NewRequestAuthenticator`.
2. **The BFF session cookie,** through the same authenticator, followed by
   the cookie-write check below.
3. **`Options.Authenticators`,** in order, for requests the first two do not
   recognize.

**Inactive principals.** `relyingparty` already refuses an inactive local
principal at sign-in, on every session request and on every token request,
so the package adds no lookup of its own. Applications drop the second
`GetPrincipal` they make today.

**Cookie writes.** A request authenticated by the cookie with an unsafe
method must carry an `Origin` (or, without one, a `Referer`) equal to
`PublicURL` or an allowed origin, and a JSON content type. Otherwise it is
refused with `ErrForbidden`. This is the check applications now write
themselves, and it is always on.

**Results.**

- `Middleware(true)` sends `401` with the challenge when there is no
  principal, and `403` for `ErrForbidden`.
- `Middleware(false)` lets requests without credentials through. Invalid
  credentials are still refused.
- Both put the `RequestPrincipal` in the context, read with
  `requestprincipal.FromContext`. Its `Native` field is the
  `*relyingparty.AuthenticatedPrincipal`.
- `Authenticate` returns the same principal, or an error wrapping
  `ErrUnauthenticated` or `ErrForbidden`, for applications that resolve the
  principal inside a framework such as huma. No application needs to record
  a fake response to read `BearerMiddleware`'s answer.

**Challenge** sets `WWW-Authenticate` with the `DPoP` scheme, the
`algs="ES256"` parameter and, for a refused token, `error="invalid_token"`.
It also sends a `Bearer` challenge when API keys or unbound tokens are
allowed.

**Acting as someone else.** An application that lets an adult act as a
managed principal replaces the principal after authentication with
`requestprincipal.WithPrincipal`, setting `Actor` to the adult. The package
adds nothing for this. The guide shows the pattern.

### Calling SystemAuth for the person

`SessionToken(r)` returns the access token of the request's BFF session,
refreshed if needed. A request that presented its own token gets
`ErrNoSessionToken`. That token is bound to the caller's key, and the
application cannot make proofs for it.

`Transport(base)` is `Client().Transport(base)`. A managed-principal client
is then:

```go
mp := mpclient.New(issuer+"/managed-principals", &http.Client{Transport: auth.Transport(nil)})
```

### Resource metadata

With `ResourceName` set, `ResourceMetadataHandler` serves RFC 9728 metadata
for `/.well-known/oauth-protected-resource`. It lists the resource
(`PublicURL`), the authorization server (`Issuer`), `dpop_bound_access_tokens_required:
true` unless unbound tokens are allowed, and the resource name.

## Postgres Principal Store

`relyingparty/pgstore` gains a `PrincipalStore` for applications that keep
principals in a plain table:

```go
func NewPrincipalStore(db *sql.DB, opts ...Option) (*PrincipalStore, error)
const PrincipalsTable = "sf_rp_principals" // created by EnsureSchema

func (s *PrincipalStore) SetActive(ctx context.Context, id string, active bool) error
func (s *PrincipalStore) Delete(ctx context.Context, id string) error
```

- **Columns:**
  - `id uuid` (the primary key, set to the SystemAuth subject when the
    principal is created)
  - `sf_principal_id`, `type`, `email`, `email_verified`
  - `display_name`, `avatar_url`
  - `active`, `managed`
  - `created_at`, `updated_at`
- **Indexes:** partial unique indexes on `sf_principal_id` and
  `lower(email)` where they are not null.
- **Errors:** a unique violation maps to `relyingparty.ErrSubjectLinked` or
  `ErrEmailConflict`, detected by SQLSTATE `23505` and the index name, with
  no driver-specific types.
- **Schema.** The table is added to `SchemaSQL`, so `EnsureSchema` creates it
  with the session and login-state tables.
- **Moving an existing table.** An application with its own principals table
  copies its rows into `sf_rp_principals` in one migration of its own, keeping
  each `id` so its foreign keys still hold, then repoints those keys and drops
  its table. The guide gives the SQL for the common column layout (`id`,
  `sf_principal_id`, `type`, `email`, `email_verified`, `display_name`,
  `avatar_url`, `active`, timestamps).
- **Tests:** it passes `relyingparty/storetest`.

Applications with their own schema, such as an Ent principal using
`identity/ent/mixin.PrincipalMixin`, keep their own store.

## Documentation

- **A new guide, "Authenticating an application":** configuration, the DPoP
  key, memberships, the middleware, calling SystemAuth for the person, acting
  as someone else, and hosts relabeling errors.
- **`systemauth/relying-party.md`:** the setup example sets `DPoPKey`, and
  points at the guide as the usual way.
- **`session/bff` and `session/jwt`** pages say that they are for
  applications issuing their own tokens, and that an application signing in
  through SystemAuth uses `identity/appauth`.
- **v0.26.0 release notes and changelog.**

## Security

- **The package does not weaken defaults:** no DPoP key, unbound tokens and
  API keys each need an explicit option, and each logs a warning at startup.
- **One origin check** for every application: cookie writes are refused
  without a matching origin and a JSON body, which stops cross-site form
  posts.
- **No new token handling.** Tokens are verified, bound and forwarded by
  `relyingparty`.

## Testing

- **Unit:**
  - each validation message;
  - key parsing and the thumbprint;
  - the membership filter;
  - the authentication order;
  - cookie writes from another origin or with a form content type;
  - challenges;
  - `SessionToken` for a session request and a token request.
- **End to end,** against an embedded SystemAuth that requires DPoP nonces:
  - sign in;
  - restart with the same key and stores, still signed in, then refresh;
  - `Bearer` refused with a `DPoP` challenge;
  - a token from another client refused unless accepted;
  - a managed principal created with `Transport`.
- **Store conformance** for `pgstore.PrincipalStore`, against Postgres in the
  integration workflow.
