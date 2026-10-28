# Authenticating an Application

An application that signs people in through SystemAuth is a relying party.
`identity/appauth` puts the [relying party](../systemauth/relying-party.md)
together for one application, so every application on SystemForge signs
people in, keeps sessions and authenticates API requests the same way:

- **Browsers** sign in through the `/bff/*` cookie session. The session's
  SystemAuth tokens are bound to the application's DPoP key.
- **Programs** call the API with DPoP-bound SystemAuth access tokens. A
  command-line tool gets them with
  [`identity/publicclient`](dpop-clients.md).
- **Organizations** come from the `orgs` claim, kept to those where the
  person holds one of the application's roles.

## Configuration

`ConfigFromEnv` reads the settings from environment variables with a
prefix:

| Variable | Setting |
| --- | --- |
| `APP_SYSTEMAUTH_ISSUER` | SystemAuth's issuer URL |
| `APP_CLIENT_ID`, `APP_CLIENT_SECRET` | The application's OAuth client at SystemAuth |
| `APP_PUBLIC_URL` | The origin the application is reached at, such as `https://notes.example.com` |
| `APP_ALLOWED_ORIGINS` | Other origins that may call the BFF, comma-separated |
| `APP_ACCESS_TOKEN_AUDIENCE` | An audience access tokens must carry |
| `APP_ACCEPTED_CLIENT_IDS` | Other clients whose tokens the API accepts, such as a command-line tool's |
| `APP_DPOP_KEY` or `APP_DPOP_KEY_FILE` | The application's DPoP key, or a file holding it |

Register the client at SystemAuth with the redirect URI that
`Config.RedirectURL` returns: the public URL followed by
`/bff/auth/callback`.

`Validate` reports every problem at once, each starting with the setting's
label, such as:

```text
PublicURL (APP_PUBLIC_URL) must use https (http is allowed only for a loopback host), got "http://notes.example.com"
DPoPKey (APP_DPOP_KEY) is required (generate one with openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256)
```

A host that reads its configuration from a file can relabel the errors by
replacing the part in parentheses with its own key, such as
`notes.dpop_key_file`, or pass its own `Labels`.

## The DPoP Key

The application proves possession of a P-256 key to SystemAuth, which binds
every session's tokens to it. The key must survive restarts and be the same
on every instance. Otherwise a session signed in on one instance cannot
refresh on another, and every deploy signs everyone out.
SystemAuth needs the same of its token HMAC secret, which signs the
refresh tokens ([Deploying SystemAuth](../systemauth/deployment.md#token-hmac-secret)).

Generate it once per deployment and keep it:

```bash
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 > notes-dpop-key.pem
```

A deploy that writes secrets into a one-line-per-value environment file
cannot hold a multi-line PEM. Deliver the key as a file and set
`APP_DPOP_KEY_FILE`. When a deployment moves to another host, copy the key;
a new key signs everyone out.

`Options.EphemeralDPoPKey` lets the application start without a key, for
local development only. A key is then generated per process, and `New` logs
a warning.

## Building the Authenticator

```go
cfg, labels := appauth.ConfigFromEnv("APP")
if err := cfg.Validate(labels); err != nil {
	return err
}
stores, err := pgstore.NewStores(db, pgstore.KeysFromEnv("APP"))
if err != nil {
	return err
}
auth, err := appauth.New(ctx, cfg, appauth.Options{
	Principals:  stores.Principals,
	Sessions:    stores.Sessions,
	LoginStates: stores.LoginStates,
	Application: "notes",
	KnownRole:   notes.KnownRole,
	Labels:      &labels,
})
if err != nil {
	return err
}

mux.Handle(auth.BasePath()+"/", auth.Handler())
mux.Handle("/api/", auth.Middleware(true)(api))
```

`New` refuses to start without session and login-state stores unless the
public URL is a loopback host. A host that embeds SystemAuth passes its
metadata as `Options.Metadata`, so no discovery request is made.

DPoP proofs are checked against `Options.ReplayCache`, by default an
in-memory cache that sees only its own instance's proofs. For a public URL
`New` logs a warning about it unless `Options.SingleInstance` declares that
one instance serves the API; with several instances pass a shared cache
such as `middleware.NewRedisReplayCache`.

### Memberships

With `Application` set, a person's memberships are the organizations where
the `orgs` claim gives them a role in that application, and `KnownRole`
accepts the role. The browser session and the API see the same
organizations.

An application that keeps its own membership tables passes
`relyingparty.LocalMemberships(store)` as `Options.Memberships` instead.

## Authenticating Requests

`Middleware(true)` refuses a request without credentials with a `401` and a
`DPoP` challenge. `Middleware(false)` lets it through without a principal.
Either way, it puts the principal in the request context:

```go
p, ok := requestprincipal.FromContext(r.Context())
// p.PrincipalID is the application's own principal ID.
// p.Native.(*relyingparty.AuthenticatedPrincipal).Memberships has the organizations.
```

The order is: the `Authorization` header, then the session cookie, then
`Options.Authenticators`, such as an AAuth authenticator for agents.

`relyingparty` makes two further checks, so applications don't repeat them:

- **Cookie writes.** A cookie-authenticated request that changes state must
  carry an `Origin` of the public URL or an allowed origin, which browsers
  send, and may then have any body, including a file upload. A request
  without an `Origin` must have a JSON body. Otherwise it gets a `403`.
- **Inactive principals.** An inactive principal is refused at sign-in and
  on every request.

An application that resolves the principal inside a framework calls
`Authenticate` instead. Its error wraps `ErrUnauthenticated` or
`ErrForbidden`, and `Challenges(err)` gives the `WWW-Authenticate` values to
send.

### Acting as someone else

An application that lets one person act as another, such as a guardian
playing as a child, replaces the principal after authentication:

```go
child := &requestprincipal.RequestPrincipal{
	PrincipalID: childID, Type: requestprincipal.TypeHuman,
	Actor: adult.PrincipalID, Protocol: adult.Protocol,
}
next.ServeHTTP(w, r.WithContext(requestprincipal.WithPrincipal(r.Context(), child)))
```

## Calling SystemAuth for the Person

To call one of SystemAuth's APIs, such as the managed-principal API, for the
signed-in person, take the session's token and send it through `Transport`,
which adds the DPoP proof SystemAuth requires:

```go
tok, err := auth.SessionToken(r)
if err != nil {
	return err // ErrNoSessionToken: no browser session
}
mp := mpclient.New(issuer+"/managed-principals", &http.Client{Transport: auth.Transport(nil)})
```

Only a session's token can be forwarded. A request that presented its own
token gets `ErrNoSessionToken`, because that token is bound to the caller's
key and the application cannot make proofs for it.

## Options That Loosen the Defaults

Each is off unless set, and logs a warning at startup.

| Option | Effect |
| --- | --- |
| `EphemeralDPoPKey` | Start without a DPoP key (local development) |
| `AllowBearerTokens` | Accept unbound tokens with the Bearer scheme, from clients SystemAuth exempts from DPoP |
| `APIKeys` | Accept static API keys. **Deprecated:** use `publicclient` sign-in for command-line tools and service accounts for automation |

## Moving to `sf_rp_principals`

`pgstore.PrincipalStore` keeps principals in `sf_rp_principals`, which
`EnsureSchema` creates. An application with its own principals table moves
its rows once, keeping each `id` so the rows that refer to them still hold.
For the common layout:

```sql
BEGIN;
INSERT INTO sf_rp_principals
    (id, sf_principal_id, type, email, email_verified, display_name,
     avatar_url, active, created_at, updated_at)
SELECT id, sf_principal_id, type, nullif(email, ''), email_verified,
       display_name, avatar_url, active, created_at, updated_at
FROM auth_principals;

-- Repoint each foreign key, for example:
ALTER TABLE notes DROP CONSTRAINT notes_owner_id_fkey;
ALTER TABLE notes ADD CONSTRAINT notes_owner_id_fkey
    FOREIGN KEY (owner_id) REFERENCES sf_rp_principals (id);

DROP TABLE auth_principals;
COMMIT;
```

Run it after `EnsureSchema` and before the application starts with the new
store. A table that marks managed principals copies that column into
`managed`.

## Protected Resource Metadata

`ResourceMetadataHandler` serves RFC 9728 metadata at
`/.well-known/oauth-protected-resource`. It lists the application's URL, its
SystemAuth, and that tokens must be DPoP-bound. Set `Options.ResourceName`
to name the application in it.
