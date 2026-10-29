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

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/oauthclient"
	"github.com/plexusone/systemforge/session/ratelimit"
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

	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode

	credentials    credential.Service
	loginTokenRate ratelimit.Storage
	loginTokenIP   ratelimit.Limit
	loginTokenCli  ratelimit.Limit

	loginTokenClientIP func(r *http.Request) string

	signupGate      SignupGate
	signupDeniedURL string
	agePage         SignupAgePage

	waitlist     SignupWaitlist
	waitlistPage WaitlistPage

	signupCodes SignupCodeLookup
	signupPage  SignupPage
}

// WithSocialAuthzSyncer sets the authorization syncer that registers principals and
// personal organizations created by social login, so they exist in
// relationship-based authorization (rebac) mode. It applies to the default
// Ent-backed directory; a directory supplied with WithPrincipalDirectory is
// responsible for its own registration. mode selects strict (a failed
// registration fails the login, rows stay committed) or eventual (logged).
func WithSocialAuthzSyncer(syncer authz.RelationshipSyncer, mode authz.SyncMode) Option {
	return func(s *Server) {
		s.socialOpts.syncer = syncer
		s.socialOpts.syncMode = mode
	}
}

// WithPrincipalDirectory sets the principal store used by social login.
// Defaults to an Ent directory when the server uses EntStorage, otherwise an
// in-memory directory.
func WithPrincipalDirectory(dir PrincipalDirectory) Option {
	return func(s *Server) { s.socialOpts.directory = dir }
}

// WithLoginSessionStore sets the store for __Host-sf_login sessions.
// Defaults to an EntLoginSessionStore when the server uses EntStorage,
// otherwise an in-memory (single-instance) store.
func WithLoginSessionStore(store LoginSessionStore) Option {
	return func(s *Server) { s.socialOpts.sessions = store }
}

// WithLoginStateStore sets the store for in-flight upstream OAuth state.
// Defaults to an EntLoginStateStore when the server uses EntStorage,
// otherwise an in-memory (single-instance) store.
func WithLoginStateStore(store oauthclient.StateStore) Option {
	return func(s *Server) { s.socialOpts.states = store }
}

// WithConsentStore sets the store for user consent decisions made on the
// /consent page. Defaults to an EntConsentStore when the server uses
// EntStorage, otherwise an in-memory (single-instance) store.
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
	// signupDenied is where a refused sign-up is redirected; nil answers 403
	// unless a waitlist is served.
	signupDenied *url.URL
	// agePage is the age question's wording, used when
	// cfg.SignupMinimumAge is set.
	agePage SignupAgePage
	// waitlist, when set, is served at SignupWaitlistPath and receives
	// refused sign-ups without signupDenied.
	waitlist         SignupWaitlist
	waitlistPage     WaitlistPage
	waitlistRates    ratelimit.Storage
	waitlistClientIP func(r *http.Request) string
	consents         ConsentStore
	redirects        *redirectPolicy
	cookies          loginCookies
	now              func() time.Time

	// signupCodes, when set, serves the sign-up page at SignupPath and
	// carries invite codes to the sign-up gate.
	signupCodes SignupCodeLookup
	signupPage  SignupPage

	// limit checks a handler limit per client address on the server's
	// rate limit storage; false means it answered the request.
	limit func(w http.ResponseWriter, r *http.Request, name string, limit ratelimit.Limit) bool

	// loginTokens exchanges managed principals' login tokens for
	// sessions; nil when managed principals are off.
	loginTokens *loginTokenExchange

	// clients looks up OAuth clients for the consent page.
	clients interface {
		GetClientByID(ctx context.Context, id string) (*Client, error)
	}
	// oauth2 answers denied authorization requests.
	oauth2 fosite.OAuth2Provider
	// revoker revokes a principal's tokens on logout; nil when the storage
	// does not support it.
	revoker SubjectTokenRevoker

	// emit records security events (Server.emitEvent).
	emit func(context.Context, *audit.Event)

	// mail sends verification links and verifyTokens keeps their tokens;
	// both are nil when mail is not configured (ADR-003).
	mail         *mailer
	verifyTokens VerificationTokenStore
	// emailChanger changes a principal's email after the new address is
	// proven; nil when the directory cannot, or mail is not configured.
	emailChanger PrincipalEmailChanger
}

func newSocialLogin(s *Server, cfg *SocialLoginConfig) (*socialLogin, error) {
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
	// Managed principals sign in with login tokens through the same
	// browser sessions, so they need no social provider.
	if len(connectors) == 0 && !s.managedPrincipalsEnabled() {
		return nil, fmt.Errorf("%w: no providers configured", ErrInvalidSocialLoginConfig)
	}
	providers := make([]string, 0, len(connectors))
	for name := range connectors {
		providers = append(providers, name)
	}
	sort.Strings(providers)

	sl := &socialLogin{
		emit:       s.emitEvent,
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
		limit:      s.limitRequest,

		mail:         s.mail,
		verifyTokens: s.verificationTokens,
	}
	if cfg.InsecureCookies {
		s.logger.Warn("systemauth: InsecureCookies is set; login, state and sign-up cookies are not Secure. Use it for local development over plain HTTP only")
	}
	if revoker, ok := s.storage.(SubjectTokenRevoker); ok {
		sl.revoker = revoker
	}
	// With Ent storage, login sessions, upstream login state and consents
	// default to the shared database so restarts keep users signed in and
	// replicas share state. Otherwise they default to single-instance
	// in-memory stores.
	if es, ok := s.storage.(*EntStorage); ok {
		if sl.consents == nil {
			sl.consents = NewEntConsentStore(es.db)
		}
		if sl.states == nil {
			sl.states = NewEntLoginStateStore(es.db)
		}
		if sl.sessions == nil {
			sl.sessions = NewEntLoginSessionStore(es.db)
		}
	}
	if sl.consents == nil {
		sl.consents = NewMemoryConsentStore()
	}
	if sl.states == nil {
		sl.states = oauthclient.NewMemoryStateStore()
	}
	if sl.sessions == nil {
		s.logger.Warn("social login using in-memory login sessions; users are signed out on restart and sessions are not shared between instances")
		sl.sessions = NewMemoryLoginSessionStore()
	}
	sl.setupLoginTokens(s)
	if sl.directory == nil {
		if es, ok := s.storage.(*EntStorage); ok {
			var dirOpts []EntPrincipalDirectoryOption
			if s.socialOpts.syncer != nil {
				dirOpts = append(dirOpts,
					WithDirectoryAuthzSyncer(s.socialOpts.syncer),
					WithDirectorySyncMode(s.socialOpts.syncMode),
					WithDirectoryLogger(s.logger))
			}
			sl.directory = NewEntPrincipalDirectory(es.db, dirOpts...)
		} else if ms, ok := s.storage.(*MemoryStorage); ok {
			s.logger.Warn("social login using in-memory principals; principals will not persist")
			sl.directory = ms.PrincipalDirectory()
		} else {
			s.logger.Warn("social login using in-memory principal directory; principals will not persist")
			sl.directory = NewMemoryPrincipalDirectory()
		}
	}
	// The sign-up wrappers below hide the directory's other methods, so
	// the email changer is taken from the directory itself.
	if c, ok := sl.directory.(PrincipalEmailChanger); ok && sl.mail != nil {
		sl.emailChanger = c
	}
	denied, err := parseSignupDeniedURL(s.socialOpts.signupDeniedURL)
	if err != nil {
		return nil, err
	}
	sl.signupDenied = denied
	if c := s.socialOpts.signupCodes; c != nil {
		if rt := s.socialOpts.signupPage.ReturnTo; rt != "" {
			if _, err := redirects.validate(rt); err != nil {
				return nil, fmt.Errorf("signup page return_to %q: %w", rt, err)
			}
		}
		sl.signupCodes, sl.signupPage = c, s.socialOpts.signupPage
	}
	if s.socialOpts.waitlist != nil || s.socialOpts.signupCodes != nil {
		sl.waitlist, sl.waitlistPage = s.socialOpts.waitlist, s.socialOpts.waitlistPage
		sl.waitlistRates, sl.waitlistClientIP = s.socialOpts.loginTokenRate, s.clientIP
		if sl.waitlistRates == nil {
			sl.waitlistRates = s.rates
		}
	}
	if err := validateSignupMinimumAge(cfg.SignupMinimumAge); err != nil {
		return nil, err
	}
	if cfg.SignupMinimumAge > 0 {
		sl.agePage = s.socialOpts.agePage.withDefaults()
		sl.directory = &ageCheckedDirectory{PrincipalDirectory: sl.directory}
	}
	if gate := s.socialOpts.signupGate; gate != nil {
		sl.directory = &gatedDirectory{PrincipalDirectory: sl.directory, gate: gate, logger: s.logger}
	}
	return sl, nil
}

func (sl *socialLogin) registerRoutes(r chi.Router) {
	// Without social providers, browser login exists only for login
	// tokens, so there is nothing to choose or call back to.
	if len(sl.providers) > 0 {
		r.Get(LoginPath, sl.handleChooser)
		r.Get(loginStartPattern, sl.handleStart)
		r.Get(loginCallbackPattern, sl.handleCallback)
		if sl.cfg.SignupMinimumAge > 0 {
			r.Get(SignupAgePath, sl.handleAgePage)
			r.Post(SignupAgePath, sl.handleAgeAnswer)
		}
		if sl.signupCodes != nil {
			r.Get(SignupPath, sl.handleSignupPage)
		}
		if sl.mail != nil {
			r.Get(VerifyEmailPath, sl.handleVerifyEmailPage)
			r.Post(VerifyEmailResendPath, sl.handleVerifyEmailResend)
			r.Get(VerifyEmailConfirmPath, sl.handleVerifyEmailConfirmPage)
			r.Post(VerifyEmailConfirmPath, sl.handleVerifyEmailConfirm)
		}
	}
	if sl.emailChanger != nil {
		r.Get(AccountEmailPath, sl.handleAccountEmailPage)
		r.Post(AccountEmailPath, sl.handleAccountEmailRequest)
		r.Post(AccountEmailCancelPath, sl.handleAccountEmailCancel)
		r.Get(AccountEmailConfirmPath, sl.handleAccountEmailConfirmPage)
		r.Post(AccountEmailConfirmPath, sl.handleAccountEmailConfirm)
	}
	r.Get(LogoutPath, sl.handleLogoutPage)
	r.Post(LogoutPath, sl.handleLogout)
	r.Get(ConsentPath, sl.handleConsentPage)
	r.Post(ConsentPath, sl.handleConsent)
	if sl.waitlist != nil {
		r.Get(SignupWaitlistPath, sl.handleWaitlistPage)
		r.Post(SignupWaitlistPath, sl.handleWaitlistJoin)
	}
	if sl.loginTokens != nil {
		r.Post(LoginTokenPath, sl.handleLoginToken)
	}
}

// noStore keeps a response out of caches. The referrer policy and the
// other security headers are set on every response (securityHeaders).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

var chooserTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in{{with .ClientName}} to {{.}}{{end}}</title></head>
<body><main>{{if .LogoURL}}<img src="{{.LogoURL}}" alt="" width="64" height="64">
{{end}}<h1>Sign in</h1>{{with .ClientName}}<p>to continue to {{.}}</p>{{end}}<ul>
{{range .Links}}<li><a href="{{.URL}}">Continue with {{.Name}}</a></li>
{{end}}</ul></main></body></html>
`))

// chooserBranding returns the name and logo of the client whose
// authorization request returnTo is, for the login page; empty when
// returnTo is not an authorization request of a known client. The logo is
// kept only when it is an https URL whose origin can be named in the
// page's content security policy.
func (sl *socialLogin) chooserBranding(r *http.Request, returnTo string) (name, logoURL, logoOrigin string) {
	target, err := parseConsentTarget(returnTo)
	if err != nil {
		return "", "", ""
	}
	client, err := sl.clients.GetClientByID(r.Context(), target.clientID)
	if err != nil {
		if !errors.Is(err, ErrClientNotFound) {
			LoggerFromContext(r.Context()).Error("loading client for the login page", "client_id", target.clientID, "error", err)
		}
		return "", "", ""
	}
	name = client.Name
	if name == "" {
		name = client.ID
	}
	if client.LogoURL == "" || ValidateClientLogoURL(client.LogoURL) != nil {
		return name, "", ""
	}
	u, err := url.Parse(client.LogoURL)
	if err != nil {
		return name, "", ""
	}
	host := strings.ToLower(u.Host)
	if !cspHost.MatchString(host) {
		return name, "", ""
	}
	return name, client.LogoURL, "https://" + host
}

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
	// A login started by an authorization request names the client.
	clientName, logoURL, logoOrigin := sl.chooserBranding(r, returnTo)
	if logoOrigin != "" {
		allowImageSource(w, logoOrigin)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := chooserTemplate.Execute(w, struct {
		ClientName, LogoURL string
		Links               []link
	}{clientName, logoURL, links}); err != nil {
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

	if !sl.limit(w, r, "social_login_start", DefaultSocialLoginLimit) {
		return
	}
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

	if err := sl.keepInviteCode(w, r); err != nil {
		logger.Error("keeping invite code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
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

	if !sl.limit(w, r, "social_login_callback", DefaultSocialLoginLimit) {
		return
	}
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
		sl.signInRefused(ctx, provider, "", "upstream_denied")
		http.Error(w, "login was cancelled or denied", http.StatusBadRequest)
		return
	}

	// The state must match the cookie set on this browser (login CSRF) and
	// must exist server-side (single use, unexpired).
	state := q.Get("state")
	if state == "" || stateCookie == "" ||
		subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie)) != 1 {
		sl.signInRefused(ctx, provider, "", "invalid_state")
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	data, err := sl.states.Take(ctx, state)
	if err != nil {
		if !errors.Is(err, oauthclient.ErrInvalidState) {
			logger.Error("reading login state", "error", err)
		}
		sl.signInRefused(ctx, provider, "", "invalid_state")
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	// Entries the age question keeps share the store; they are never
	// upstream state.
	if data.Provider != provider || data.Nonce == signupAgePending || data.Nonce == signupAgeConfirmed {
		sl.signInRefused(ctx, provider, "", "invalid_state")
		http.Error(w, "invalid login state", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		sl.signInRefused(ctx, provider, "", "missing_code")
		http.Error(w, "missing authorization code", http.StatusBadRequest)
		return
	}

	token, err := conn.Exchange(ctx, code, oauth2.VerifierOption(data.PKCEVerifier))
	if err != nil {
		logger.Warn("upstream code exchange failed", "provider", provider, "error", err)
		sl.signInRefused(ctx, provider, "", "upstream_exchange_failed")
		http.Error(w, "upstream login failed", http.StatusBadGateway)
		return
	}
	user, err := conn.FetchUser(ctx, token)
	if err != nil {
		logger.Warn("upstream profile fetch failed", "provider", provider, "error", err)
		sl.signInRefused(ctx, provider, "", "upstream_profile_failed")
		http.Error(w, "upstream login failed", http.StatusBadGateway)
		return
	}

	if sl.cfg.SignupMinimumAge > 0 {
		ctx = sl.takeAgeConfirmation(ctx, w, r, provider)
	}
	ctx = sl.withSignupCode(ctx, r)
	login := ExternalLogin{
		Provider:           provider,
		Subject:            user.ProviderID,
		Email:              user.Email,
		EmailVerified:      user.EmailVerified,
		EmailAuthoritative: AuthoritativeEmail(user),
		Name:               user.Name,
		Username:           user.Username,
		AvatarURL:          user.AvatarURL,
	}
	p, err := ResolveExternalLogin(ctx, sl.directory, login, sl.now())
	// With mail configured, an unverified provider email is held for
	// verification instead of refused (ADR-003).
	if errors.Is(err, ErrEmailNotVerified) && sl.canVerifyEmail(login) {
		sl.startEmailVerification(ctx, w, r, login, data.RedirectURL)
		return
	}
	sl.completeSignIn(ctx, w, r, provider, data.RedirectURL, p, err)
}

// completeSignIn finishes a sign-in that ResolveExternalLogin resolved to
// p, or answers its error: it establishes the login session and redirects
// to redirectURL, re-validated in case the policy changed mid-flow.
func (sl *socialLogin) completeSignIn(ctx context.Context, w http.ResponseWriter, r *http.Request, provider, redirectURL string, p *HumanPrincipal, err error) {
	logger := LoggerFromContext(ctx)
	if err != nil {
		status, msg := http.StatusInternalServerError, "login failed"
		if reason := signInRefusalReason(err); reason != "" {
			sl.signInRefused(ctx, provider, "", reason)
		}
		switch {
		case errors.Is(err, ErrEmailNotVerified):
			status, msg = http.StatusForbidden, "a verified email address is required to sign in"
		case errors.Is(err, ErrEmailConflict):
			status, msg = http.StatusConflict, "an account with this email already exists; sign in the way you signed in before"
		case errors.Is(err, ErrPrincipalInactive):
			status, msg = http.StatusForbidden, "account is disabled"
		case errors.Is(err, errSignupAgeRequired):
			target, rErr := sl.redirects.resolve(redirectURL)
			if rErr != nil {
				target = sl.redirects.defaultTarget
			}
			sl.askAge(w, r, provider, target)
			return
		case errors.Is(err, ErrSignupNotInvited):
			logger.Info("sign-up refused: not invited", "provider", provider)
			if sl.signupDenied == nil && sl.waitlist != nil {
				http.Redirect(w, r, SignupWaitlistPath+"?error=invite_required", http.StatusSeeOther)
				return
			}
			if sl.signupDenied != nil {
				u := *sl.signupDenied
				q := u.Query()
				q.Set("error", "invite_required")
				u.RawQuery = q.Encode()
				http.Redirect(w, r, u.String(), http.StatusSeeOther)
				return
			}
			status, msg = http.StatusForbidden, "sign-up is by invitation only"
		default:
			logger.Error("resolving principal for social login", "provider", provider, "error", err)
		}
		http.Error(w, msg, status)
		return
	}

	// The login resolved to an account, new or existing: the invite code
	// has done its job.
	sl.clearSignupCode(w, r)

	// Re-validate the stored target in case the policy changed mid-flow.
	target, err := sl.redirects.resolve(redirectURL)
	if err != nil {
		target = sl.redirects.defaultTarget
	}

	if err := sl.establishSession(ctx, w, r, p.ID, provider); err != nil {
		logger.Error("creating login session", "error", err)
		sl.signInRefused(ctx, provider, "", "server_error")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	logger.Info("social login succeeded", "provider", provider, "principal_id", p.ID)
	sl.signedIn(ctx, p.ID, provider, "")
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

// ValidateReturnTo checks a place to send a person after an action, by the
// policy sign-in uses for return_to: an absolute path on this host, or a URL
// on an allowed redirect origin. It returns the URL to use, or
// ErrRedirectNotAllowed, which it also returns when social login is not
// enabled.
func (s *Server) ValidateReturnTo(raw string) (string, error) {
	if s.social == nil {
		return "", ErrRedirectNotAllowed
	}
	return s.social.redirects.validate(raw)
}

// socialSessionProvider makes the authorization endpoint recognize the
// social login session and send unauthenticated users to /login.
type socialSessionProvider struct {
	inner SessionProvider
	// trustInner reports whether the wrapped provider is consulted after
	// the login cookie.
	trustInner bool
	social     *socialLogin
}

var _ SessionProvider = (*socialSessionProvider)(nil)

func newSocialSessionProvider(inner SessionProvider, sl *socialLogin) *socialSessionProvider {
	// The default provider authenticates nobody unless a trusted header was
	// configured explicitly, so consulting it cannot bypass social login
	// unless the operator asked for that.
	return &socialSessionProvider{inner: inner, trustInner: true, social: sl}
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

func (p *socialSessionProvider) socialPrincipal(ctx context.Context, userID string) (*HumanPrincipal, bool) {
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
// checked against the consent store filled by the /consent page. The
// authorization endpoint asks only about clients that are not first-party.
func (p *socialSessionProvider) HasConsent(ctx context.Context, userID, clientID string, scopes []string) bool {
	if _, ok := p.socialPrincipal(ctx, userID); !ok {
		return p.inner.HasConsent(ctx, userID, clientID, scopes)
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
	// A human with an active manager is a managed principal (ADR-009);
	// relying parties need to know regardless of the scopes granted.
	if lp.Managed {
		claims[ManagedClaim] = true
	}
	for _, scope := range scopes {
		switch scope {
		case "email":
			if lp.Email == "" {
				continue
			}
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
