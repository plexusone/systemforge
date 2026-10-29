// Package appauth assembles identity/relyingparty for one application, so
// every application that signs people in through SystemAuth does it the same
// way, with the same defaults:
//
//   - Browsers sign in through the /bff/* cookie session. The session's
//     SystemAuth tokens are bound to the application's DPoP key, which is
//     required, so sessions survive restarts and are shared by instances.
//   - Programs call the API with DPoP-bound SystemAuth access tokens; the
//     Bearer scheme is refused unless explicitly allowed.
//   - A cookie-authenticated request that changes state must come from an
//     allowed origin with a JSON body (relyingparty's check).
//   - Inactive principals are refused at sign-in and on every request
//     (relyingparty's check).
//   - Memberships come from the orgs claim, kept to the organizations where
//     the principal holds one of the application's roles.
//
// New returns an Authenticator: mount Handler at the base path, and protect
// the API with Middleware or call Authenticate. Other protocols, such as AAuth
// for agents, chain after the built-in ones through Options.Authenticators.
package appauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/plexusone/systemforge/identity/appcatalog"
	"github.com/plexusone/systemforge/identity/relyingparty"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/middleware"
)

// Options are the storage ports and choices of an Authenticator. Every option
// that loosens a default is off unless set, and logs a warning when set.
type Options struct {
	// Principals is the application's principal store (required).
	Principals relyingparty.PrincipalStore
	// Sessions stores browser sessions, and LoginStates in-flight sign-ins.
	// Both are required unless PublicURL is a loopback host, where the
	// in-memory stores are used and sessions end at a restart. Use
	// pgstore.NewStores in production.
	Sessions    relyingparty.SessionStore
	LoginStates relyingparty.LoginStateStore

	// Application is the application's key in an organization's
	// applications (the orgs claim's apps). When set, the default
	// membership source keeps only organizations where the principal holds
	// a role of it that KnownRole accepts (any role when KnownRole is nil).
	Application string
	KnownRole   func(role string) bool
	// Memberships replaces the default membership source, the orgs claim
	// with SystemAuth's memberships endpoint as fallback. It is used as is:
	// Application does not filter it. Pass relyingparty.LocalMemberships for
	// an application that keeps its own membership tables.
	Memberships relyingparty.MembershipSource

	// Apps lists the deployment's application catalog in the browser
	// session, for the product switcher.
	Apps appcatalog.Source
	// Metadata is SystemAuth's provider metadata, when the host already has
	// it (an embedded SystemAuth). Without it, New discovers it.
	Metadata *relyingparty.Metadata
	// HTTPClient makes the calls to SystemAuth. Default: http.DefaultClient.
	HTTPClient *http.Client
	// Revocation, when set, applies recorded access changes to sessions and
	// tokens at once (ADR-010).
	Revocation *relyingparty.RevocationCache
	// LoginErrorPath, when set, is the app's sign-in page: a browser whose
	// sign-in fails is redirected there with ?error=<CODE> instead of shown
	// a JSON error. See relyingparty.BFFConfig.LoginErrorPath.
	LoginErrorPath string
	// ReplayCache rejects reused DPoP proofs. Default: in memory, per
	// instance; instances that share an API need a shared cache. Unless
	// the public URL is a loopback host or SingleInstance is set, New
	// logs a warning when it uses the default.
	ReplayCache relyingparty.DPoPReplayCache
	// SingleInstance declares that one instance serves the API, so the
	// default in-memory replay cache sees every proof.
	SingleInstance bool
	// Authenticators are tried after the session and token, for requests
	// they do not recognize, such as AAuth-signed agent requests.
	Authenticators []requestprincipal.Authenticator

	// ServiceAccounts accepts SystemAuth service accounts' tokens: their
	// client (relyingparty.ServiceAccountClientID) is accepted, and an
	// account's local principal is created on its first request
	// (relyingparty.BearerConfig.ServicePrincipals). Principals must support
	// service identities, as pgstore.PrincipalStore does.
	ServiceAccounts bool

	// EphemeralDPoPKey lets the application start without a DPoP key: one
	// is generated per process, so people sign in again after every
	// restart. For local development only.
	EphemeralDPoPKey bool
	// AllowBearerTokens also accepts unbound access tokens with the Bearer
	// scheme, from clients SystemAuth exempts from DPoP.
	AllowBearerTokens bool

	// ResourceName names the application in its protected resource
	// metadata (RFC 9728).
	ResourceName string
	// Labels name the settings in New's configuration errors. Default:
	// DefaultLabels.
	Labels *Labels
	// Logger receives warnings and operational errors. Default:
	// slog.Default().
	Logger *slog.Logger
}

// Authenticator authenticates an application's requests and serves its
// /bff/* surface.
type Authenticator struct {
	cfg      Config
	client   *relyingparty.Client
	bff      *relyingparty.BFF
	chain    requestprincipal.Chain
	unbound  bool
	resource string
	name     string
	logger   *slog.Logger
}

// New builds the Authenticator: the relying-party client, from
// Options.Metadata or by discovery, the BFF, and the request authentication
// chain.
func New(ctx context.Context, cfg Config, opts Options) (*Authenticator, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	labels := DefaultLabels
	if opts.Labels != nil {
		labels = *opts.Labels
	}
	if err := cfg.validate(labels, !opts.EphemeralDPoPKey); err != nil {
		return nil, fmt.Errorf("appauth: %w", err)
	}
	if opts.Principals == nil {
		return nil, errors.New("appauth: Options.Principals is required")
	}
	if err := checkStores(cfg, opts, logger); err != nil {
		return nil, err
	}
	key, hasKey, err := cfg.dpopKey()
	if err != nil {
		return nil, fmt.Errorf("appauth: %s: %w", labels.DPoPKey, err)
	}
	warn(opts, labels, hasKey, logger)

	client, err := newClient(ctx, relyingparty.Config{
		Issuer:              cfg.Issuer,
		ClientID:            cfg.ClientID,
		ClientSecret:        cfg.ClientSecret,
		RedirectURL:         cfg.RedirectURL(),
		Scopes:              scopes(cfg.Scopes),
		AccessTokenAudience: cfg.AccessTokenAudience,
		AcceptedClientIDs:   cfg.acceptedClientIDs(serviceClients(opts)...),
		HTTPClient:          opts.HTTPClient,
		DPoPKey:             key,
	}, opts.Metadata)
	if err != nil {
		return nil, fmt.Errorf("appauth: SystemAuth client: %w", err)
	}
	memberships := membershipSource(client, opts, logger)
	bff, err := relyingparty.NewBFF(relyingparty.BFFConfig{
		Client:          client,
		Principals:      opts.Principals,
		Memberships:     memberships,
		Apps:            opts.Apps,
		Revocation:      opts.Revocation,
		LoginErrorPath:  opts.LoginErrorPath,
		Sessions:        opts.Sessions,
		LoginStates:     opts.LoginStates,
		BasePath:        cfg.basePath(),
		AllowedOrigins:  cfg.AllowedOrigins,
		InsecureCookies: cfg.insecureCookies(),
		Logger:          logger,
	})
	if err != nil {
		return nil, fmt.Errorf("appauth: BFF: %w", err)
	}
	replay := opts.ReplayCache
	if replay == nil {
		if !opts.SingleInstance && !cfg.loopback() {
			logger.Warn("appauth: DPoP proofs are checked against an in-memory replay cache; pass Options.ReplayCache shared by every instance, or set Options.SingleInstance when one instance serves the API")
		}
		replay = middleware.NewMemoryReplayCache()
	}
	a := &Authenticator{
		cfg:      cfg,
		client:   client,
		bff:      bff,
		unbound:  opts.AllowBearerTokens,
		resource: strings.TrimRight(cfg.PublicURL, "/"),
		name:     opts.ResourceName,
		logger:   logger,
	}
	own := &ownAuthenticator{
		inner: relyingparty.NewRequestAuthenticator(relyingparty.BearerConfig{
			Tokens:            client,
			Principals:        opts.Principals,
			Memberships:       memberships,
			Sessions:          bff,
			Revocation:        opts.Revocation,
			DPoP:              &relyingparty.DPoPConfig{ReplayCache: replay, BaseURL: a.resource},
			AllowBearerTokens: opts.AllowBearerTokens,
			ServicePrincipals: opts.ServiceAccounts,
			Logger:            logger,
		}),
		bearer: opts.AllowBearerTokens,
	}
	a.chain = append(requestprincipal.Chain{own}, opts.Authenticators...)
	return a, nil
}

// serviceClients is the client of service-account tokens when they are
// accepted.
func serviceClients(opts Options) []string {
	if opts.ServiceAccounts {
		return []string{relyingparty.ServiceAccountClientID}
	}
	return nil
}

func checkStores(cfg Config, opts Options, logger *slog.Logger) error {
	if opts.Sessions != nil && opts.LoginStates != nil {
		return nil
	}
	if !cfg.loopback() {
		return errors.New("appauth: Options.Sessions and Options.LoginStates are required unless the public URL is a loopback host")
	}
	logger.Warn("appauth: sessions are kept in memory, so people sign in again after a restart")
	return nil
}

func warn(opts Options, l Labels, hasKey bool, logger *slog.Logger) {
	if !hasKey {
		logger.Warn("appauth: no DPoP key: browser sessions cannot refresh after a restart, so people sign in again",
			"setting", l.DPoPKey, "generate", DPoPKeyCommand)
	}
	if opts.AllowBearerTokens {
		logger.Warn("appauth: unbound bearer access tokens are accepted; a copied token works for whoever holds it")
	}
	if opts.Memberships != nil && opts.Application != "" {
		logger.Warn("appauth: Options.Memberships is set, so Options.Application does not filter memberships",
			"application", opts.Application)
	}
}

// scopes adds extra to relyingparty.DefaultScopes, or returns nil (the
// default) when there are none.
func scopes(extra []string) []string {
	if len(extra) == 0 {
		return nil
	}
	out := slices.Clone(relyingparty.DefaultScopes)
	for _, s := range extra {
		if s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func newClient(ctx context.Context, cfg relyingparty.Config, md *relyingparty.Metadata) (*relyingparty.Client, error) {
	if md == nil {
		return relyingparty.NewClient(ctx, cfg)
	}
	if strings.TrimRight(md.Issuer, "/") != strings.TrimRight(cfg.Issuer, "/") {
		return nil, fmt.Errorf("metadata issuer %q does not match %q", md.Issuer, cfg.Issuer)
	}
	if md.AuthorizationEndpoint == "" || md.TokenEndpoint == "" || md.JWKSURI == "" {
		return nil, errors.New("metadata is missing the authorization, token or keys endpoint")
	}
	return relyingparty.NewClientWithMetadata(cfg, *md)
}

func membershipSource(client *relyingparty.Client, opts Options, logger *slog.Logger) relyingparty.MembershipSource {
	if opts.Memberships != nil {
		return opts.Memberships
	}
	src := relyingparty.ClaimsOrRemoteMemberships(relyingparty.RemoteMemberships(client), logger)
	if opts.Application == "" {
		return src
	}
	return applicationMemberships(src, opts.Application, opts.KnownRole)
}

// applicationMemberships keeps the organizations where the principal holds a
// role of application that known accepts, so the browser session and the API
// see the same tenants.
func applicationMemberships(src relyingparty.MembershipSource, application string, known func(string) bool) relyingparty.MembershipSource {
	return relyingparty.MembershipSourceFunc(func(ctx context.Context, q relyingparty.MembershipQuery) ([]relyingparty.Membership, error) {
		ms, err := src.Memberships(ctx, q)
		if err != nil {
			return nil, err
		}
		out := make([]relyingparty.Membership, 0, len(ms))
		for _, m := range ms {
			role := m.Applications[application]
			if role == "" || (known != nil && !known(role)) {
				continue
			}
			out = append(out, m)
		}
		return out, nil
	})
}

// Handler serves the /bff/* surface; mount it at BasePath.
func (a *Authenticator) Handler() http.Handler { return a.bff }

// BasePath is where Handler is mounted.
func (a *Authenticator) BasePath() string { return a.cfg.basePath() }

// Client is the relying-party client, for calls to SystemAuth.
func (a *Authenticator) Client() *relyingparty.Client { return a.client }

// BFF is the browser session handler.
func (a *Authenticator) BFF() *relyingparty.BFF { return a.bff }

// RequestAuthenticator is the authentication chain, to combine with other
// requestprincipal middleware.
func (a *Authenticator) RequestAuthenticator() requestprincipal.Authenticator { return a.chain }

// Middleware authenticates each request and puts its
// requestprincipal.RequestPrincipal in the context (requestprincipal.FromContext;
// its Native is the *relyingparty.AuthenticatedPrincipal for the built-in
// methods). With required, a request without credentials gets a 401 with
// the challenges; without it, it passes with no principal. Invalid
// credentials are refused either way, and a cross-origin cookie write gets a
// 403.
func (a *Authenticator) Middleware(required bool) func(http.Handler) http.Handler {
	return requestprincipal.Middleware(requestprincipal.Options{Optional: !required, Logger: a.logger}, a.chain)
}

// Authenticate resolves a request to its principal, for applications that
// resolve it inside a framework rather than in middleware. A refusal wraps
// ErrUnauthenticated or ErrForbidden and a *requestprincipal.Error, whose
// Write sends the response the protocol prescribes; Challenges gives its
// WWW-Authenticate values.
func (a *Authenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	p, err := a.chain.Authenticate(r)
	if err == nil {
		return p, nil
	}
	var rpErr *requestprincipal.Error
	if !errors.As(err, &rpErr) {
		return nil, fmt.Errorf("appauth: authenticating the request: %w", err)
	}
	if rpErr.Status == http.StatusForbidden {
		return nil, &authError{sentinel: ErrForbidden, rp: rpErr}
	}
	return nil, &authError{sentinel: ErrUnauthenticated, rp: rpErr}
}

// Challenge adds the WWW-Authenticate challenges for a request without
// credentials: DPoP, Bearer when unbound tokens are accepted, and
// those of Options.Authenticators.
func (a *Authenticator) Challenge(h http.Header) { a.chain.Challenge(h) }

// SessionToken returns the access token of the request's browser session,
// refreshed when about to expire, to call SystemAuth's APIs for the person
// with Transport. A request that presented its own credential gets
// ErrNoSessionToken: its token is bound to the caller's key, and the
// application cannot make proofs for it.
func (a *Authenticator) SessionToken(r *http.Request) (string, error) {
	if r.Header.Get("Authorization") != "" || r.Header.Get("X-API-Key") != "" {
		return "", ErrNoSessionToken
	}
	tok, err := a.bff.AccessToken(r)
	if errors.Is(err, relyingparty.ErrSessionNotFound) {
		return "", fmt.Errorf("%w: %w", ErrNoSessionToken, err)
	}
	if err != nil {
		return "", fmt.Errorf("appauth: session token: %w", err)
	}
	return tok, nil
}

// Transport returns a RoundTripper for requests to SystemAuth that carry a
// session token in Authorization: it presents a bound token with the DPoP
// scheme and a proof by the application's key. See
// relyingparty.Client.Transport.
func (a *Authenticator) Transport(base http.RoundTripper) http.RoundTripper {
	return a.client.Transport(base)
}

// ownAuthenticator is relyingparty's authenticator with challenges that name
// only the schemes the application accepts.
type ownAuthenticator struct {
	inner  *relyingparty.RequestAuthenticator
	bearer bool
}

func (o *ownAuthenticator) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	return o.inner.Authenticate(r)
}

func (o *ownAuthenticator) Challenge(h http.Header) {
	h.Add("WWW-Authenticate", DPoPChallenge)
	if o.bearer {
		h.Add("WWW-Authenticate", `Bearer realm="api"`)
	}
}

var (
	_ requestprincipal.Authenticator = (*ownAuthenticator)(nil)
	_ requestprincipal.Challenger    = (*ownAuthenticator)(nil)
)
