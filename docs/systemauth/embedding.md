# Embedding SystemAuth in a Host Binary

The `cmd/systemauth` binary is a thin wrapper around the
`identity/systemauthsvc` package. A host binary that serves several
applications from one Go process (routing by `Host` header) can use the same
package to run a production-grade SystemAuth next to them, with the same
configuration file, production checks, database setup and stores as the
standalone server.

## Security trade-off

Read this before choosing embedding over the standalone binary.

- **The signing key shares the process with application code.** Anything that
  can read the host's memory, or any code path in any embedded application
  that leaks process state (a debug endpoint, a heap dump, a dependency with
  a vulnerability), can expose the key that signs every ID and access token.
  With the standalone binary only SystemAuth's own code runs next to the key.
- **A host restart is a login outage.** Deploying, crashing or rolling back
  any application restarts SystemAuth too. Login sessions, in-flight logins,
  consent grants and tokens survive in the database, but requests during the
  restart fail, and a crash loop in one application takes login down for all.
- **Shared resource limits.** A memory leak or CPU spike in one application
  affects token issuance for all relying parties.

Embedding is reasonable when the host runs a small set of first-party
applications from one codebase and one deployment pipeline, and running a
separate service is not worth the operational cost. Keep SystemAuth on its
own host name (`auth.example.com`) so its `__Host-` cookies are not shared
with the applications. Prefer the standalone binary when third-party code runs
in the host or when the applications deploy independently.

## Setup

```go
import (
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

cfg, err := systemauthsvc.LoadConfig("/etc/host/systemauth.yaml",
	systemauthsvc.WithDefaultSigningKeyPEM(os.Getenv("SYSTEMAUTH_SIGNING_KEY")),
)
if err != nil {
	return err
}
auth, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
	Logger:  logger,
	Migrate: true,
})
if err != nil {
	return err // e.g. ErrNotProductionReady: missing key, http issuer, no database
}
defer func() {
	if err := auth.Close(); err != nil {
		logger.Error("closing SystemAuth", "error", err)
	}
}()

// An application in the same process federates to SystemAuth without
// fetching the discovery document.
rp, err := relyingparty.NewClientWithMetadata(relyingparty.Config{
	Issuer:      auth.Issuer(),
	ClientID:    "app",
	RedirectURL: "https://app.example.com/bff/auth/callback",
}, auth.Metadata())
if err != nil {
	return err
}

mux := http.NewServeMux()
mux.Handle("auth.example.com/", auth.Handler())
mux.Handle("app.example.com/", appHandler)
```

Overrides are applied before defaults and validation, so an override can
fill in a value the file leaves out (for example `WithDefaultIssuer` for a
file without `issuer`). When the SystemAuth settings live inside the host's
own configuration file, load them from memory with the same overrides:

```go
// section is the raw YAML or JSON of the host's "systemauth" block.
cfg, err := systemauthsvc.LoadConfigBytes(section, "yaml",
	systemauthsvc.WithDefaultIssuer("http://localhost:8080"),
	systemauthsvc.WithDefaultSigningKeyPEM(os.Getenv("SYSTEMAUTH_SIGNING_KEY")),
)
```

`Handler()` serves every SystemAuth endpoint at the root of the issuer's host
(discovery, JWKS, `/oauth/*`, `/login/*`, `/logout`, `/consent`, `/healthz`,
`/readyz`); mount it on its own host name rather than under a path prefix,
since endpoint URLs are derived from the issuer.

The relying party still calls the token, JWKS and UserInfo endpoints over
HTTP at the issuer URL, so the host must be reachable at that URL from
itself (normally through the same reverse proxy).

## API

| Item | Purpose |
|------|---------|
| `LoadConfig(path, overrides...)` | Read YAML/JSON (with `${ENV}` expansion), then apply overrides, defaults and validation, in that order. An empty path starts from an empty config. |
| `LoadConfigBytes(data, format, overrides...)` | The same for configuration already in memory. `format` is `"yaml"`, `"json"` or `""` (JSON when the data starts with `{`, otherwise YAML). |
| `systemauth.DecodeConfig`, `systemauth.DecodeConfigFile` | Lower level: decode and expand `${ENV}` without defaults or validation; call `ApplyDefaults` and `Validate` after adjusting the result. |
| `WithIssuer`, `WithDefaultIssuer`, `WithDatabase`, `WithSigningKeyFile`, `WithDefaultSigningKeyPEM`, `WithKeyID` | Overrides, the same ones the command's flags use. |
| `Options.Dev` | Allow an ephemeral key, in-memory storage, an http issuer and insecure cookies. Never in production. |
| `Options.Logger` | `*slog.Logger`; `NewLogger(w, level, format)` builds one. |
| `Options.SigningKey` | An `*rsa.PrivateKey` from a secret manager, instead of a file or PEM. |
| `Options.DB` + `DBDialect`, `Options.EntClient` | Use an existing pool or Ent client (the caller keeps ownership; `Close` leaves it open). |
| `Options.Migrate` | Create or update the schema before the system user and static clients are written. |
| `Options.ServerOptions` | Extra `systemauth.Option`s, e.g. `WithObservability`. |
| `CheckProduction(cfg, opts)` | The checks `New` enforces, for a `validate` command. |
| `Migrate(ctx, cfg)` | Open, migrate and close (for a separate migration step). |
| `Service.Handler`, `Ready`, `Migrate`, `Close`, `Issuer`, `KeyID`, `Metadata`, `Discovery`, `Server` | The running service. |

`New` enforces the [production requirements](deployment.md#production-requirements)
whenever `Options.Dev` is false: a signing key, a public https issuer, a
persistent database (configured or injected), and no
`social_login.insecure_cookies`. It then connects, optionally migrates,
creates the system user that owns statically configured clients, registers
or updates those clients, and keeps tokens, login sessions, in-flight logins
and consent grants in the database (see
[Production Stores](production-stores.md)).

`Ready(ctx)` runs the same checks as `GET /readyz` (the database ping); wire it
into the host's own readiness endpoint.

## Database

The package links the PostgreSQL (`pgx`) and SQLite (`go-sqlite3`, cgo)
drivers. SystemAuth's tables can share a PostgreSQL database with the host's
applications only if their schemas do not collide; a separate database (or
`Options.DB` on a dedicated database) is simpler to operate and to back up.
