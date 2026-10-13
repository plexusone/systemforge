package systemauthsvc

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/plexusone/connectionforge/provider"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/connections"
	"github.com/plexusone/systemforge/identity/appcatalog"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/signupgate"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/keys"
	"github.com/plexusone/systemforge/marketplace"
)

// dbPingTimeout bounds the connectivity check New performs.
const dbPingTimeout = 10 * time.Second

// Options configures New with what does not belong in the configuration
// file: the deployment mode, the logger, programmatic secrets and injected
// database handles. The issuer, database DSN, signing key file and key ID
// are configuration fields; set them in the file, through LoadConfig
// overrides, or directly on the Config.
type Options struct {
	// Dev relaxes the production requirements: an ephemeral signing key,
	// in-memory storage, an http issuer and insecure login cookies are
	// allowed. Never set it for a deployment that serves real users.
	Dev bool

	// Logger receives server logs. Default: slog.Default().
	Logger *slog.Logger

	// SigningKey supplies the RSA signing key programmatically (e.g. from a
	// secret manager), taking precedence over keys.private_key_file and
	// keys.private_key_pem.
	SigningKey *rsa.PrivateKey

	// DB injects an open connection pool instead of opening
	// cfg.Database. DBDialect names its database ("postgres" or "sqlite")
	// and is required with DB. The caller owns DB; Close does
	// not close it.
	DB        *sql.DB
	DBDialect string

	// EntClient injects an Ent client for the identity schema instead of
	// opening a database. When DB is also set it is used for the readiness
	// ping. The caller owns the client; Close does not close it.
	EntClient *ent.Client

	// Migrate creates or updates the database schema before the system
	// user and static clients are written. Without it the schema must
	// already exist (run Migrate or "systemauth migrate" first).
	Migrate bool

	// Vocabularies declares the application roles of the products hosted on
	// this SystemAuth (ADR-007). With a database, New emits the orgs claim
	// (organizations, the principal's role in each, and per-application
	// roles in "apps"), so relying parties read memberships from tokens
	// instead of keeping their own tables. Without it the claim lists
	// organizations with empty "apps".
	Vocabularies *authz.VocabularyRegistry

	// DefaultEntitlements names the registered applications every
	// organization is entitled to without buying anything: the deployment's
	// marketplace default entitlements (marketplace.WithDefaultEntitlements).
	// An organization's owner holds the top role of each, and other members
	// hold the roles assigned to them. Applications not named here are
	// closed to every organization.
	DefaultEntitlements []string

	// Apps is the deployment's application catalog (appcatalog), published
	// at appcatalog.WellKnownPath for the products' switchers. Each entry's
	// ID should be an application with a registered vocabulary.
	Apps *appcatalog.Catalog

	// InviteOnly makes social login create accounts only for verified
	// emails that hold a sign-up invite (see Service.SignupInvites). People
	// who already have an account are unaffected. It needs a database,
	// since invites are stored there.
	InviteOnly bool

	// SignupDeniedURL is where a refused sign-up is redirected, with
	// error=invite_required in the query. Without it, an invite-only
	// deployment sends refused sign-ups to its own waitlist page
	// (systemauth.SignupWaitlistPath). It must be absolute https (http only
	// for a loopback host).
	SignupDeniedURL string

	// WaitlistPage is the wording of the waitlist page an invite-only
	// deployment serves; empty fields take systemauth.DefaultWaitlistPage.
	// Submissions are stored in the database (see Service.SignupWaitlist).
	WaitlistPage systemauth.WaitlistPage

	// Providers are the connection providers the hosted applications support,
	// used when the configuration enables connections. Optional.
	Providers *provider.Registry

	// ServerOptions are passed to systemauth.NewEmbedded after the storage,
	// logger and readiness options New sets, e.g. WithObservability or
	// custom social login stores. They come last, so they can replace the
	// orgs source New sets.
	ServerOptions []systemauth.Option
}

// Service is a configured SystemAuth server ready to be mounted.
type Service struct {
	cfg         Config
	server      *systemauth.Server
	client      *ent.Client
	db          *sql.DB
	owned       *Database
	storageName string
	// dialect is the Ent dialect of the database, or "" when unknown (an
	// injected Ent client without Options.DBDialect) or in-memory.
	dialect string
	logger  *slog.Logger

	// keys, authz and conns are set when connections are enabled.
	keys  *keys.Keys
	authz *mode.Result
	conns *connections.Connections
}

// New builds a SystemAuth server from cfg. Unless opts.Dev is set it
// refuses a configuration that misses a production requirement (see
// CheckProduction). With a database it connects, optionally migrates,
// bootstraps the system user that owns statically configured clients,
// registers or updates those clients, and keeps tokens, login sessions,
// login state and consent grants in the database. Without one (Dev only)
// everything is in memory.
func New(ctx context.Context, cfg *Config, opts Options) (*Service, error) {
	if cfg == nil {
		return nil, errors.New("systemauthsvc: nil config")
	}
	c := *cfg
	if opts.SigningKey != nil {
		c.Keys.PrivateKey = opts.SigningKey
		c.Keys.PrivateKeyPEM = ""
		c.Keys.PrivateKeyFile = ""
	}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	if err := CheckProduction(&c, opts); err != nil {
		return nil, err
	}
	if err := c.Keys.LoadSigningKey(); err != nil {
		return nil, err
	}
	if opts.DB != nil && opts.EntClient == nil {
		if opts.DBDialect == "" {
			return nil, errors.New("systemauthsvc: Options.DBDialect is required with Options.DB")
		}
		_, dialectName, err := driverDialect(opts.DBDialect)
		if err != nil {
			return nil, fmt.Errorf("systemauthsvc: Options.DBDialect: %w", err)
		}
		opts.DBDialect = dialectName
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if opts.Dev {
		logger.Warn("development mode: production safeguards are disabled")
	}

	s := &Service{cfg: c, storageName: "in-memory", logger: logger}
	if err := s.openStorage(ctx, &c, opts); err != nil {
		s.closeQuietly()
		return nil, err
	}
	if err := s.openConnections(ctx, &c, opts); err != nil {
		s.closeQuietly()
		return nil, err
	}

	serverOpts := []systemauth.Option{systemauth.WithLogger(logger)}
	if s.client != nil {
		if opts.Migrate {
			logger.Info("running database migrations")
			if err := s.Migrate(ctx); err != nil {
				s.closeQuietly()
				return nil, err
			}
		}
		ownerID, created, err := ensureSystemPrincipal(ctx, s.client)
		if err != nil {
			s.closeQuietly()
			return nil, fmt.Errorf("creating system principal: %w", err)
		}
		if created {
			logger.Info("created the system principal that owns statically configured clients")
		}
		serverOpts = append(serverOpts,
			systemauth.WithStorage(systemauth.NewEntStorage(s.client, systemauth.WithDefaultOwner(ownerID))),
			systemauth.WithReadinessCheck("database", s.ping),
		)
		if c.SocialLogin != nil {
			// systemauth keeps the login session, login state and consent
			// stores in the Ent database (sf_login_sessions,
			// sf_login_states, sf_consent_grants) when it uses EntStorage,
			// so restarts keep users signed in and replicas share state.
			logger.Info("social login state stored in the database", "storage", s.storageName)
		}
	} else {
		logger.Warn("using in-memory storage (data will not persist)")
	}
	if err := systemauth.ValidateSignupDeniedURL(opts.SignupDeniedURL); err != nil {
		s.closeQuietly()
		return nil, fmt.Errorf("systemauthsvc: Options.SignupDeniedURL: %w", err)
	}
	if opts.InviteOnly && s.client == nil {
		s.closeQuietly()
		return nil, errors.New("systemauthsvc: Options.InviteOnly needs a database to hold invites")
	}
	if s.client != nil && opts.InviteOnly {
		serverOpts = append(serverOpts,
			systemauth.WithSignupGate(signupgate.NewGate(signupgate.NewStore(s.client))),
			systemauth.WithSignupWaitlist(signupgate.NewWaitlist(s.client), opts.WaitlistPage),
		)
		logger.Info("sign-up is by invitation only", "waitlist", systemauth.SignupWaitlistPath)
	}
	if opts.Apps != nil {
		serverOpts = append(serverOpts, systemauth.WithAppCatalog(opts.Apps))
		if opts.Vocabularies != nil {
			for _, a := range opts.Apps.Apps() {
				if _, ok := opts.Vocabularies.Get(a.ID); !ok {
					logger.Warn("app catalog lists an application with no registered vocabulary; nobody holds a role in it", "app", a.ID)
				}
			}
		}
	}
	if opts.SignupDeniedURL != "" {
		serverOpts = append(serverOpts, systemauth.WithSignupDeniedURL(opts.SignupDeniedURL))
	}
	if s.client != nil {
		src, err := orgsSource(ctx, s.client, opts, logger)
		if err != nil {
			s.closeQuietly()
			return nil, err
		}
		serverOpts = append(serverOpts, systemauth.WithOrgsSource(src))
	}
	serverOpts = append(serverOpts, opts.ServerOptions...)

	server, err := systemauth.NewEmbedded(c, serverOpts...)
	if err != nil {
		s.closeQuietly()
		return nil, fmt.Errorf("creating server: %w", err)
	}
	s.server = server
	s.mountConnections()
	return s, nil
}

// orgsSource builds the source of the orgs claim. Application roles come
// from approle over opts.Vocabularies, with entitlements from the
// marketplace's default entitlements; with no vocabularies the claim
// carries organizations only.
func orgsSource(ctx context.Context, client *ent.Client, opts Options, logger *slog.Logger) (systemauth.OrgsSource, error) {
	if opts.Vocabularies == nil {
		if len(opts.DefaultEntitlements) > 0 {
			return nil, errors.New("systemauthsvc: Options.DefaultEntitlements requires Options.Vocabularies")
		}
		return systemauth.NewEntOrgsSource(client, nil), nil
	}
	registered := opts.Vocabularies.Apps()
	for _, app := range opts.DefaultEntitlements {
		if !slices.Contains(registered, app) {
			return nil, fmt.Errorf("systemauthsvc: default entitlement %q has no registered vocabulary", app)
		}
	}
	defaults := marketplace.WithDefaultEntitlements(opts.DefaultEntitlements...)
	if _, err := marketplace.WarnIfNoEntitlements(ctx, logger, nil, registered, defaults); err != nil {
		return nil, err
	}
	entitlements := marketplace.EntitlementSource(nil, nil, nil, defaults)
	roleOpts := append([]approle.Option{approle.WithLogger(logger)}, marketplace.ApproleOptions(entitlements)...)
	return systemauth.NewEntOrgsSource(client, approle.NewService(client, opts.Vocabularies, roleOpts...)), nil
}

// openStorage selects the injected Ent client or connection pool, or
// opens and pings the configured database.
func (s *Service) openStorage(ctx context.Context, c *Config, opts Options) error {
	switch {
	case opts.EntClient != nil:
		s.client, s.db, s.storageName = opts.EntClient, opts.DB, "ent"
		if opts.DBDialect != "" {
			_, dialectName, err := driverDialect(opts.DBDialect)
			if err != nil {
				return fmt.Errorf("systemauthsvc: Options.DBDialect: %w", err)
			}
			s.storageName, s.dialect = opts.DBDialect, dialectName
		}
	case opts.DB != nil:
		d := wrapDB(opts.DB, opts.DBDialect)
		s.client, s.db, s.storageName, s.dialect = d.Client, d.DB, opts.DBDialect, opts.DBDialect
	case c.Database != nil:
		s.logger.Info("connecting to database", "driver", c.Database.Driver)
		d, err := OpenDatabase(c.Database)
		if err != nil {
			return err
		}
		s.owned = d
		s.client, s.db, s.storageName, s.dialect = d.Client, d.DB, c.Database.Driver, d.Dialect
	default:
		return nil
	}
	pingCtx, cancel := context.WithTimeout(ctx, dbPingTimeout)
	defer cancel()
	if err := s.ping(pingCtx); err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	return nil
}

// ping checks database connectivity: a pool ping when the pool is known,
// otherwise a minimal query through the Ent client.
func (s *Service) ping(ctx context.Context) error {
	if s.db != nil {
		return s.db.PingContext(ctx)
	}
	_, err := s.client.Principal.Query().Limit(1).IDs(ctx)
	return err
}

// Handler returns the HTTP handler serving every SystemAuth endpoint
// (discovery, JWKS, OAuth, UserInfo, health and, when configured, social
// login). Mount it at the root of the issuer's host.
func (s *Service) Handler() http.Handler { return s.server }

// ServeHTTP implements http.Handler.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.server.ServeHTTP(w, r) }

// Server returns the underlying SystemAuth server.
func (s *Service) Server() *systemauth.Server { return s.server }

// SignupInvites returns the store of sign-up invites over the service's
// database, for an operator command to add, list and revoke them. It is nil
// without a database. Invites only take effect when Options.InviteOnly is
// set.
func (s *Service) SignupInvites() *signupgate.Store {
	if s.client == nil {
		return nil
	}
	return signupgate.NewStore(s.client)
}

// SignupWaitlist returns the waitlist over the service's database, for an
// operator command to list, export and remove entries. It is nil without a
// database. The page that fills it is served only when Options.InviteOnly
// is set.
func (s *Service) SignupWaitlist() *signupgate.Waitlist {
	if s.client == nil {
		return nil
	}
	return signupgate.NewWaitlist(s.client)
}

// Config returns the effective configuration (defaults applied).
func (s *Service) Config() Config { return s.cfg }

// Issuer returns the public issuer URL.
func (s *Service) Issuer() string { return s.cfg.Issuer }

// KeyID returns the JWKS key ID of the signing key.
func (s *Service) KeyID() string { return s.server.KeyID() }

// StorageName names the storage backend: the database driver or dialect,
// "ent" for an injected client, or "in-memory".
func (s *Service) StorageName() string { return s.storageName }

// EntClient returns the Ent client, or nil with in-memory storage.
func (s *Service) EntClient() *ent.Client { return s.client }

// Discovery returns the OpenID Provider configuration served at
// /.well-known/openid-configuration.
func (s *Service) Discovery() systemauth.OpenIDConfiguration {
	return s.server.OpenIDConfiguration()
}

// Metadata returns the provider metadata a relying party needs, identical
// to what discovery serves. Pass it to relyingparty.NewClientWithMetadata
// so an in-process relying party skips the discovery request.
func (s *Service) Metadata() relyingparty.Metadata {
	d := s.server.OpenIDConfiguration()
	return relyingparty.Metadata{
		Issuer:                d.Issuer,
		AuthorizationEndpoint: d.AuthorizationEndpoint,
		TokenEndpoint:         d.TokenEndpoint,
		UserinfoEndpoint:      d.UserinfoEndpoint,
		JWKSURI:               d.JwksURI,
		RevocationEndpoint:    d.RevocationEndpoint,
	}
}

// Migrate creates or updates the database schema. It is idempotent and
// does nothing with in-memory storage.
func (s *Service) Migrate(ctx context.Context) error {
	if s.client == nil {
		return nil
	}
	if err := migrate(ctx, s.client, s.dialect); err != nil {
		return err
	}
	if s.conns != nil {
		return s.conns.Migrate(ctx)
	}
	return nil
}

// Ready runs the readiness checks behind GET /readyz (the database ping)
// and returns nil when the service can serve requests.
func (s *Service) Ready(ctx context.Context) error {
	return s.server.Ready(ctx)
}

// Close releases the database New opened. Injected handles (Options.DB,
// Options.EntClient) are left to their owner.
func (s *Service) Close() error {
	err := s.closeConnections()
	if s.owned == nil {
		return err
	}
	d := s.owned
	s.owned = nil
	return errors.Join(err, d.Close())
}

// closeQuietly closes after a failed New; the setup error is what the
// caller needs, so a close failure is only logged.
func (s *Service) closeQuietly() {
	if err := s.Close(); err != nil {
		s.logger.Error("closing database", "error", err)
	}
}
