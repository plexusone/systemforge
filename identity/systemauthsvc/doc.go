// Package systemauthsvc assembles a production-grade SystemAuth OAuth 2.0 /
// OpenID Connect server from configuration, for the standalone systemauth
// command and for host binaries that embed SystemAuth next to other
// applications in one process.
//
// It owns the steps between a configuration file and a ready
// http.Handler:
//
//   - LoadConfig: read the YAML/JSON configuration (with environment
//     variable expansion), apply overrides, defaults and validation.
//   - New: enforce the production requirements (signing key, https issuer,
//     persistent database, secure cookies) unless Options.Dev is set; open
//     PostgreSQL ("pgx") or SQLite ("sqlite3") or use an injected *sql.DB or
//     Ent client; optionally migrate; bootstrap the system user that owns
//     statically configured clients; register or update those clients; and
//     select the Ent-backed token, login session, login state and consent
//     stores so restarts and replicas share state.
//   - Service: the http.Handler plus Migrate, Ready, Close, Issuer and the
//     discovery Metadata an in-process relying party can use without a
//     network round trip.
//
// Embedding SystemAuth puts its signing key in the same process (and
// memory) as the host's application code, and a restart of the host is a
// restart of the login service. See docs/systemauth/embedding.md.
package systemauthsvc
