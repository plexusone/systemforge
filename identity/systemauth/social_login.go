package systemauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/ory/fosite"
	"golang.org/x/oauth2"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// Social login routes mounted on the SystemAuth router when
// Config.SocialLogin is set.
const (
	// LoginPath renders the provider chooser (or redirects when only one
	// provider is configured). It accepts a return_to query parameter.
	LoginPath = "/login"
	// loginStartPattern starts the upstream flow for {provider}.
	loginStartPattern = "/login/{provider}"
	// loginCallbackPattern receives the upstream redirect for {provider}.
	loginCallbackPattern = "/login/{provider}/callback"

	// loginStateTTL bounds how long an upstream login may take.
	loginStateTTL = 10 * time.Minute
)

// socialOptions carries Option-supplied social login dependencies until the
// server is built.
type socialOptions struct {
	directory  PrincipalDirectory
	sessions   LoginSessionStore
	states     oauthclient.StateStore
	consents   ConsentStore
	connectors []*oauthclient.Connector
}

// WithPrincipalDirectory sets the principal store used by social login.
// Defaults to an Ent directory when the server uses EntStorage, otherwise an
// in-memory directory.
func WithPrincipalDirectory(dir PrincipalDirectory) Option {
	return func(s *Server) { s.socialOpts.directory = dir }
}

// WithLoginSessionStore sets the store for __Host-sf_login sessions.
// Defaults to an in-memory (single-instance) store.
func WithLoginSessionStore(store LoginSessionStore) Option {
	return func(s *Server) { s.socialOpts.sessions = store }
}

// WithLoginStateStore sets the store for in-flight upstream OAuth state.
// Defaults to an in-memory (single-instance) store.
func WithLoginStateStore(store oauthclient.StateStore) Option {
	return func(s *Server) { s.socialOpts.states = store }
}

// WithConsentStore sets the store for user consent decisions made on the
// /consent page. Defaults to an in-memory (single-instance) store.
func WithConsentStore(store ConsentStore) Option {
	return func(s *Server) { s.socialOpts.consents = store }
}

// WithSocialConnector adds or replaces the upstream connector for
// c.Provider. Use it to point a provider at alternate endpoints (tests,
// GitHub Enterprise); credentials normally come from Config.SocialLogin.
func WithSocialConnector(c *oauthclient.Connector) Option {
	return func(s *Server) { s.socialOpts.connectors = append(s.socialOpts.connectors, c) }
}

// socialLogin implements GitHub/Google login on SystemAuth.
type socialLogin struct {
	cfg        *SocialLoginConfig
	connectors map[string]*oauthclient.Connector
	providers  []string
	states     oauthclient.StateStore
	sessions   LoginSessionStore
	directory  PrincipalDirectory
	consents   ConsentStore
	redirects  *redirectPolicy
	cookies    loginCookies
	now        func() time.Time

	// clients looks up OAuth clients for the consent page.
	clients interface {
		GetClientByID(ctx context.Context, id string) (*Client, error)
	}
	// oauth2 answers denied authorization requests.
	oauth2 fosite.OAuth2Provider
	// revoker revokes a principal's tokens on logout; nil when the storage
	// does not support it.
	revoker SubjectTokenRevoker
}

func newSocialLogin(s *Server) (*socialLogin, error) {
	cfg := s.config.SocialLogin
	issuer := strings.TrimRight(s.config.Issuer, "/")

	redirects, err := newRedirectPolicy(s.config.Issuer, cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSocialLoginConfig, err)
	}

	connectors := map[string]*oauthclient.Connector{}
	providerCfg := func(name string, p *SocialProviderConfig) oauthclient.ProviderConfig {
		redirect := p.RedirectURL
		if redirect == "" {
			redirect = issuer + "/login/" + name + "/callback"
		}
		return oauthclient.ProviderConfig{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			RedirectURL:  redirect,
			Scopes:       p.Scopes,
		}
	}
	if cfg.GitHub != nil {
		connectors[oauthclient.ProviderGitHub] = oauthclient.NewGitHubConnector(providerCfg(oauthclient.ProviderGitHub, cfg.GitHub))
	}
	if cfg.Google != nil {
		connectors[oauthclient.ProviderGoogle] = oauthclient.NewGoogleConnector(providerCfg(oauthclient.ProviderGoogle, cfg.Google))
	}
	for _, c := range s.socialOpts.connectors {
		if c == nil || c.OAuth2 == nil || c.Provider == "" {
			return nil, fmt.Errorf("%w: connector requires Provider and OAuth2 config", ErrInvalidSocialLoginConfig)
		}
		connectors[c.Provider] = c
	}
	if len(connectors) == 0 {
		return nil, fmt.Errorf("%w: no providers configured", ErrInvalidSocialLoginConfig)
	}
	providers := make([]string, 0, len(connectors))
	for name := range connectors {
		providers = append(providers, name)
	}
	sort.Strings(providers)

	sl := &socialLogin{
		cfg:        cfg,
		connectors: connectors,
		providers:  providers,
		states:     s.socialOpts.states,
		sessions:   s.socialOpts.sessions,
		directory:  s.socialOpts.directory,
		consents:   s.socialOpts.consents,
		redirects:  redirects,
		cookies:    newLoginCookies(cfg.InsecureCookies),
		now:        time.Now,
		clients:    s.storage,
		oauth2:     s.oauth2,
	}
	if revoker, ok := s.storage.(SubjectTokenRevoker); ok {
		sl.revoker = revoker
	}
	if sl.consents == nil {
		sl.consents = NewMemoryConsentStore()
	}
	if sl.states == nil {
		sl.states = oauthclient.NewMemoryStateStore()
	}
	if sl.sessions == nil {
		sl.sessions = NewMemoryLoginSessionStore()
	}
	if sl.directory == nil {
		if es, ok := s.storage.(*EntStorage); ok {
			sl.directory = NewEntPrincipalDirectory(es.db)
		} else {
			s.logger.Warn("social login using in-memory principal directory; principals will not persist")
			sl.directory = NewMemoryPrincipalDirectory()
		}
	}
	return sl, nil
}

func (sl *socialLogin) registerRoutes(r chi.Router) {
	r.Get(LoginPath, sl.handleChooser)
	r.Get(loginStartPattern, sl.handleStart)
	r.Get(loginCallbackPattern, sl.handleCallback)
	r.Get(LogoutPath, sl.handleLogoutPage)
	r.Post(LogoutPath, sl.handleLogout)
	r.Get(ConsentPath, sl.handleConsentPage)
	r.Post(ConsentPath, sl.handleConsent)
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

var chooserTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title></head>
<body><main><h1>Sign in</h1><ul>
{{range .}}<li><a href="{{.URL}}">Continue with {{.Name}}</a></li>
{{end}}</ul></main></body></html>
`))

var providerDisplayNames = map[string]string{
	oauthclient.ProviderGitHub: "GitHub",
	oauthclient.ProviderGoogle: "Google",
}

func startURL(provider, returnTo string) string {
	u := LoginPath + "/" + url.PathEscape(provider)
	if returnTo != "" {
		u += "?return_to=" + url.QueryEscape(returnTo)
	}
	return u
}

// handleChooser serves GET /login.
func (sl *socialLogin) handleChooser(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" {
		if _, err := sl.redirects.validate(returnTo); err != nil {
			http.Error(w, "invalid return_to", http.StatusBadRequest)
			return
		}
	}
	if len(sl.providers) == 1 {
		//nolint:gosec // G710: same-origin relative path; returnTo was validated against the allowlist and is query-escaped
		http.Redirect(w, r, startURL(sl.providers[0], returnTo), http.StatusFound)
		return
	}

	type link struct{ Name, URL string }
	links := make([]link, 0, len(sl.providers))
	for _, p := range sl.providers {
		name := providerDisplayNames[p]
		if name == "" {
			name = p
		}
		links = append(links, link{Name: name, URL: startURL(p, returnTo)})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := chooserTemplate.Execute(w, links); err != nil {
		LoggerFromContext(r.Context()).Error("rendering login page", "error", err)
	}
}

// handleStart serves GET /login/{provider}: it records state + PKCE
// verifier server-side, binds the state to the browser with a cookie, and
// redirects to the provider.
func (sl *socialLogin) handleStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)

	provider := chi.URLParam(r, "provider")
	conn, ok := sl.connectors[provider]
	if !ok {
		http.NotFound(w, r)
		return
	}

	target, err := sl.redirects.resolve(r.URL.Query().Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}

	state, err := oauthclient.GenerateState()
	if err != nil {
		logger.Error("generating login state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := sl.states.Put(ctx, state, oauthclient.StateData{
		Provider:     provider,
		RedirectURL:  target,
		PKCEVerifier: verifier,
	}, loginStateTTL); err != nil {
		logger.Error("storing login state", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sl.cookies.setState(w, state, loginStateTTL)
	//nolint:gosec // G710: redirect target is the configured provider's authorization endpoint
	http.Redirect(w, r, conn.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

// handleCallback serves GET /login/{provider}/callback.
func (sl *socialLogin) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)

	provider := chi.URLParam(r, "provider")
	conn, ok := sl.connectors[provider]
	if !ok {
		http.NotFound(w, r)
		return
	}

	q := r.URL.Query()
	stateCookie := cookieValue(r, sl.cookies.stateName)
	sl.cookies.clearState(w)

	if upstreamErr := q.Get("error"); upstreamErr != "" {
		logger.Info("upstream login denied", "provider", provider, "error", upstreamErr)
		http.Error(w, "login was cancelled or denied", http.StatusBadRequest)
		return
	}

	// The state must match the cookie set on this browser (login CSRF) and
	// must exist server-side (single use, unexpired).
	state := q.Get("state")
	if state == "" || stateCookie == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie)) != 1 {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	data, err := sl.states.Take(ctx, state)
	if err != nil {
		if !errors.Is(err, oauthclient.ErrInvalidState) {
			logger.Error("reading login state", "error", err)
		}
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	if data.Provider != provider {
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := conn.Exchange(ctx, code, oauth2.VerifierOption(data.PKCEVerifier))
	if err != nil {
		logger.Warn("upstream code exchange failed", "provider", provider, "error", err)
		http.Error(w, "upstream login failed", http.StatusBadGateway)
		return
	}
	user, err := conn.FetchUser(ctx, token)
	if err != nil {
		logger.Warn("upstream profile fetch failed", "provider", provider, "error", err)
		http.Error(w, "upstream login failed", http.StatusBadGateway)
		return
	}

	p, err := ResolveExternalLogin(ctx, sl.directory, ExternalLogin{
		Provider:      provider,
		Subject:       user.ProviderID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		AvatarURL:     user.AvatarURL,
	}, sl.now())
	if err != nil {
		status, msg := http.StatusInternalServerError, "login failed"
		switch {
		case errors.Is(err, ErrEmailNotVerified):
			status, msg = http.StatusForbidden, "a verified email address is required to sign in"
		case errors.Is(err, ErrEmailConflict):
			status, msg = http.StatusConflict, "an account with this email already exists and cannot be linked automatically"
		case errors.Is(err, ErrPrincipalInactive):
			status, msg = http.StatusForbidden, "account is disabled"
		default:
			logger.Error("resolving principal for social login", "provider", provider, "error", err)
		}
		http.Error(w, msg, status)
		return
	}

	// Re-validate the stored target in case the policy changed mid-flow.
	target, err := sl.redirects.resolve(data.RedirectURL)
	if err != nil {
		target = sl.redirects.defaultTarget
	}

	if err := sl.establishSession(ctx, w, r, p.ID, provider); err != nil {
		logger.Error("creating login session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Info("social login succeeded", "provider", provider, "principal_id", p.ID)
	http.Redirect(w, r, target, http.StatusFound)
}

// establishSession issues a fresh session token (never reusing one the
// browser presented, to prevent session fixation) and sets the cookie.
func (sl *socialLogin) establishSession(ctx context.Context, w http.ResponseWriter, r *http.Request, principalID uuid.UUID, provider string) error {
	if old := cookieValue(r, sl.cookies.sessionName); old != "" {
		if err := sl.sessions.Delete(ctx, old); err != nil {
			return fmt.Errorf("deleting previous session: %w", err)
		}
	}
	token, err := newSessionToken()
	if err != nil {
		return err
	}
	now := sl.now()
	lifetime := sl.cfg.SessionLifetime.Duration()
	if err := sl.sessions.Create(ctx, token, LoginSession{
		PrincipalID: principalID,
		Provider:    provider,
		CreatedAt:   now,
		ExpiresAt:   now.Add(lifetime),
	}); err != nil {
		return err
	}
	sl.cookies.setSession(w, token, lifetime)
	return nil
}

// currentSession returns the valid login session on r for an active
// principal, or ErrLoginSessionNotFound.
func (sl *socialLogin) currentSession(r *http.Request) (*LoginSession, error) {
	token := cookieValue(r, sl.cookies.sessionName)
	if token == "" {
		return nil, ErrLoginSessionNotFound
	}
	sess, err := sl.sessions.Get(r.Context(), token)
	if err != nil {
		return nil, err
	}
	p, err := sl.directory.GetPrincipal(r.Context(), sess.PrincipalID)
	if err != nil {
		if errors.Is(err, ErrPrincipalNotFound) {
			return nil, ErrLoginSessionNotFound
		}
		return nil, err
	}
	if !p.Active {
		return nil, ErrLoginSessionNotFound
	}
	return &sess, nil
}

// CurrentLoginSession returns the SystemAuth login session carried by r's
// __Host-sf_login cookie. It returns ErrLoginSessionNotFound when there is
// none or social login is not enabled.
func (s *Server) CurrentLoginSession(r *http.Request) (*LoginSession, error) {
	if s.social == nil {
		return nil, ErrLoginSessionNotFound
	}
	return s.social.currentSession(r)
}

// socialSessionProvider makes the authorization endpoint recognize the
// social login session and send unauthenticated users to /login.
type socialSessionProvider struct {
	inner SessionProvider
	// trustInner is false for the header-based DefaultSessionProvider, which
	// must not be able to bypass social login.
	trustInner bool
	social     *socialLogin
}

var _ SessionProvider = (*socialSessionProvider)(nil)

func newSocialSessionProvider(inner SessionProvider, sl *socialLogin) *socialSessionProvider {
	_, isDefault := inner.(*DefaultSessionProvider)
	return &socialSessionProvider{inner: inner, trustInner: !isDefault, social: sl}
}

// GetAuthenticatedUser implements SessionProvider.
func (p *socialSessionProvider) GetAuthenticatedUser(r *http.Request) string {
	sess, err := p.social.currentSession(r)
	if err == nil {
		return sess.PrincipalID.String()
	}
	if !errors.Is(err, ErrLoginSessionNotFound) {
		LoggerFromContext(r.Context()).Error("reading login session", "error", err)
	}
	if p.trustInner {
		return p.inner.GetAuthenticatedUser(r)
	}
	return ""
}

// IDPHintParam is an optional /oauth/authorize parameter naming the
// upstream provider (github, google) to sign in with, skipping the chooser.
const IDPHintParam = "idp_hint"

// RedirectToLogin implements SessionProvider. An idp_hint naming a
// configured provider sends the user straight to that provider.
func (p *socialSessionProvider) RedirectToLogin(returnURL string) string {
	if u, err := url.Parse(returnURL); err == nil {
		if hint := u.Query().Get(IDPHintParam); hint != "" {
			if _, ok := p.social.connectors[hint]; ok {
				return startURL(hint, returnURL)
			}
		}
	}
	return LoginPath + "?return_to=" + url.QueryEscape(returnURL)
}

func (p *socialSessionProvider) socialPrincipal(ctx context.Context, userID string) (*LoginPrincipal, bool) {
	id, err := uuid.Parse(userID)
	if err != nil {
		return nil, false
	}
	lp, err := p.social.directory.GetPrincipal(ctx, id)
	if err != nil {
		if !errors.Is(err, ErrPrincipalNotFound) {
			LoggerFromContext(ctx).Error("loading principal", "error", err)
		}
		return nil, false
	}
	return lp, true
}

// HasConsent implements SessionProvider. Social-login principals are
// auto-consented when skip_consent is set, and otherwise checked against
// the consent store filled by the /consent page.
func (p *socialSessionProvider) HasConsent(ctx context.Context, userID, clientID string, scopes []string) bool {
	if _, ok := p.socialPrincipal(ctx, userID); !ok {
		return p.inner.HasConsent(ctx, userID, clientID, scopes)
	}
	if p.social.cfg.SkipConsent {
		return true
	}
	ok, err := p.social.consents.HasConsent(ctx, userID, clientID, scopes)
	if err != nil {
		LoggerFromContext(ctx).Error("checking consent", "error", err)
		return false
	}
	return ok
}

// RedirectToConsent implements SessionProvider.
func (p *socialSessionProvider) RedirectToConsent(returnURL string) string {
	return ConsentPath + "?return_to=" + url.QueryEscape(returnURL)
}

// SaveConsent implements SessionProvider.
func (p *socialSessionProvider) SaveConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if _, ok := p.socialPrincipal(ctx, userID); !ok {
		return p.inner.SaveConsent(ctx, userID, clientID, scopes)
	}
	return p.social.consents.SaveConsent(ctx, userID, clientID, scopes)
}

// GetUserClaims implements SessionProvider.
func (p *socialSessionProvider) GetUserClaims(ctx context.Context, userID string, scopes []string) map[string]interface{} {
	lp, ok := p.socialPrincipal(ctx, userID)
	if !ok {
		return p.inner.GetUserClaims(ctx, userID, scopes)
	}
	claims := map[string]interface{}{"sub": userID}
	for _, scope := range scopes {
		switch scope {
		case "email":
			claims["email"] = lp.Email
			claims["email_verified"] = lp.EmailVerified
		case "profile":
			claims["name"] = lp.DisplayName
			if lp.AvatarURL != "" {
				claims["picture"] = lp.AvatarURL
			}
		}
	}
	return claims
}
