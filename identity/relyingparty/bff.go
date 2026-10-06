package relyingparty

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	// SessionCookieName is the BFF session cookie. The __Host- prefix makes
	// browsers enforce Secure, Path=/ and no Domain attribute.
	SessionCookieName = "__Host-sf_rp_session"
	// stateCookieName binds an in-flight login to the browser that started
	// it (login CSRF).
	stateCookieName = "__Host-sf_rp_state"

	insecureSessionCookieName = "sf_rp_session"
	insecureStateCookieName   = "sf_rp_state"

	loginStateTTL = 10 * time.Minute
	// refreshSkew refreshes the SystemAuth access token slightly early.
	refreshSkew = 30 * time.Second
)

// BFFConfig configures the /bff/* cookie-session handler.
type BFFConfig struct {
	// Client is the SystemAuth relying-party client (required).
	Client *Client

	// Principals resolves SystemAuth identities to app-local principals
	// (required).
	Principals PrincipalStore

	// Memberships supplies organization memberships (with the session's
	// SystemAuth claims). Default: Principals' own table when it implements
	// MembershipLister, else none.
	Memberships MembershipSource

	// Sessions stores browser sessions. Default: in-memory (single
	// instance); use pgstore.NewSessionStore in production.
	Sessions SessionStore

	// LoginStates stores in-flight logins. Default: in-memory (single
	// instance); use pgstore.NewLoginStateStore in production.
	LoginStates LoginStateStore

	// BasePath is where the handler is mounted. Default: "/bff".
	BasePath string

	// SessionLifetime is the absolute session lifetime. Default: 12h.
	SessionLifetime time.Duration

	// DefaultReturnTo is where users land after login when no return_to is
	// given. Default: "/".
	DefaultReturnTo string

	// AllowedOrigins are absolute origins (scheme://host[:port]) that may be
	// post-login return_to targets and may call the BFF's state-changing
	// endpoints. The origin of the Client's RedirectURL is always allowed.
	AllowedOrigins []string

	// InsecureCookies drops the __Host- prefix and the Secure flag for
	// local development over plain HTTP. Never enable in production.
	InsecureCookies bool

	// Logger receives operational errors. Default: slog.Default().
	Logger *slog.Logger
}

// BFF serves the /bff/* cookie-session surface of the shared frontend
// auth package:
//
//	GET  {base}/session               session status (+ user with memberships)
//	GET  {base}/api/v1/users/me       current user with memberships
//	GET  {base}/auth/login            start SystemAuth login (?return_to=)
//	GET  {base}/auth/{provider}       start login via github|google (?return_to=)
//	GET  {base}/auth/callback         OIDC callback; sets the session cookie
//	POST {base}/auth/logout           end the session, revoke SystemAuth tokens
//
// Mount it on the application's router at BasePath.
type BFF struct {
	cfg       BFFConfig
	mux       *http.ServeMux
	origins   map[string]bool
	appOrigin string
	cookies   rpCookies
	logger    *slog.Logger
	now       func() time.Time
}

// NewBFF creates the BFF handler.
func NewBFF(cfg BFFConfig) (*BFF, error) {
	if cfg.Client == nil {
		return nil, errors.New("relyingparty: BFFConfig.Client is required")
	}
	if cfg.Principals == nil {
		return nil, errors.New("relyingparty: BFFConfig.Principals is required")
	}
	if cfg.Sessions == nil {
		cfg.Sessions = NewMemorySessionStore()
	}
	cfg.Memberships = defaultMembershipSource(cfg.Memberships, cfg.Principals)
	if cfg.LoginStates == nil {
		cfg.LoginStates = NewMemoryLoginStateStore()
	}
	if cfg.BasePath == "" {
		cfg.BasePath = "/bff"
	}
	cfg.BasePath = "/" + strings.Trim(cfg.BasePath, "/")
	if cfg.SessionLifetime <= 0 {
		cfg.SessionLifetime = 12 * time.Hour
	}
	if cfg.DefaultReturnTo == "" {
		cfg.DefaultReturnTo = "/"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	appOrigin, err := parseOrigin(cfg.Client.Config().RedirectURL)
	if err != nil {
		return nil, err
	}
	b := &BFF{
		cfg:       cfg,
		origins:   map[string]bool{appOrigin: true},
		appOrigin: appOrigin,
		cookies:   newRPCookies(cfg.InsecureCookies),
		logger:    cfg.Logger,
		now:       time.Now,
	}
	for _, o := range cfg.AllowedOrigins {
		origin, err := parseOrigin(o)
		if err != nil {
			return nil, err
		}
		b.origins[origin] = true
	}
	if _, err := b.validateReturnTo(cfg.DefaultReturnTo); err != nil {
		return nil, fmt.Errorf("relyingparty: DefaultReturnTo: %w", err)
	}

	base := cfg.BasePath
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+base+"/session", b.handleSession)
	mux.HandleFunc("GET "+base+"/api/v1/users/me", b.handleMe)
	mux.HandleFunc("GET "+base+"/auth/login", b.handleLogin)
	mux.HandleFunc("POST "+base+"/auth/login", b.handlePasswordLogin)
	mux.HandleFunc("GET "+base+"/auth/callback", b.handleCallback)
	mux.HandleFunc("POST "+base+"/auth/logout", b.handleLogout)
	mux.HandleFunc("GET "+base+"/auth/{provider}", b.handleProviderLogin)
	mux.HandleFunc(base+"/", func(w http.ResponseWriter, _ *http.Request) {
		writeAuthError(w, http.StatusNotFound, "NOT_FOUND", "not found")
	})
	b.mux = mux
	return b, nil
}

// ServeHTTP implements http.Handler.
func (b *BFF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	b.mux.ServeHTTP(w, r)
}

// --- JSON shapes of the shared frontend contract ---

// SessionStatus is the GET /bff/session response.
type SessionStatus struct {
	Authenticated bool       `json:"authenticated"`
	UserID        string     `json:"user_id,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	User          *User      `json:"user,omitempty"`
}

// User is the frontend's user representation.
type User struct {
	ID          string           `json:"id"`
	Email       string           `json:"email"`
	Name        string           `json:"name"`
	AvatarURL   string           `json:"avatar_url,omitempty"`
	Memberships []UserMembership `json:"memberships"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   *time.Time       `json:"updated_at,omitempty"`
}

// UserMembership is the frontend's organization membership.
type UserMembership struct {
	ID               string    `json:"id"`
	OrganizationID   string    `json:"organization_id"`
	OrganizationName string    `json:"organization_name"`
	OrganizationSlug string    `json:"organization_slug"`
	Role             string    `json:"role"`
	JoinedAt         time.Time `json:"joined_at"`
}

// AuthError is the frontend's error shape.
type AuthError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status is already sent; an encoding failure here can only be a
	// broken connection, which the client observes directly.
	if err := json.NewEncoder(w).Encode(v); err != nil {
		return
	}
}

func writeAuthError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, AuthError{Code: code, Message: message})
}

func toUser(p *Principal, memberships []Membership) *User {
	u := &User{
		ID:          p.ID,
		Email:       p.Email,
		Name:        p.Name,
		AvatarURL:   p.AvatarURL,
		Memberships: make([]UserMembership, 0, len(memberships)),
		CreatedAt:   p.CreatedAt,
	}
	if !p.UpdatedAt.IsZero() {
		t := p.UpdatedAt
		u.UpdatedAt = &t
	}
	for _, m := range memberships {
		u.Memberships = append(u.Memberships, UserMembership(m))
	}
	return u
}

// --- sessions ---

// CurrentSession returns the session, principal and memberships carried by
// r's session cookie, or ErrSessionNotFound.
func (b *BFF) CurrentSession(r *http.Request) (*Session, *Principal, []Membership, error) {
	ctx := r.Context()
	token := cookieValue(r, b.cookies.sessionName)
	if token == "" {
		return nil, nil, nil, ErrSessionNotFound
	}
	sess, err := b.cfg.Sessions.Get(ctx, token)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := b.cfg.Principals.GetPrincipal(ctx, sess.PrincipalID)
	if errors.Is(err, ErrPrincipalNotFound) {
		return nil, nil, nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, nil, nil, err
	}
	if !p.Active {
		return nil, nil, nil, ErrSessionNotFound
	}
	memberships, err := b.cfg.Memberships.Memberships(ctx, MembershipQuery{Principal: p, Subject: sess.Subject, Claims: sess.Claims})
	if err != nil {
		return nil, nil, nil, err
	}
	return &sess, p, memberships, nil
}

// authenticate returns the session principal of r, or ErrSessionNotFound.
func (b *BFF) authenticate(r *http.Request) (*AuthenticatedPrincipal, error) {
	sess, p, memberships, err := b.CurrentSession(r)
	if err != nil {
		return nil, err
	}
	return &AuthenticatedPrincipal{
		ID:          p.ID,
		Type:        principalType(p),
		Subject:     sess.Subject,
		Method:      AuthMethodSession,
		Memberships: memberships,
	}, nil
}

// RequireSession is middleware for the application's own browser APIs: it
// requires a BFF session (401 AuthError otherwise) and puts the principal
// in the request context.
func (b *BFF) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := b.authenticate(r)
		if err != nil {
			if !errors.Is(err, ErrSessionNotFound) {
				b.logger.ErrorContext(r.Context(), "reading session", "error", err)
				writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
				return
			}
			writeAuthError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
			return
		}
		if isUnsafeMethod(r.Method) && !b.sameOriginRequest(r) {
			writeAuthError(w, http.StatusForbidden, "CSRF_REJECTED", "cross-origin request rejected")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// AccessToken returns a valid SystemAuth access token for r's session,
// refreshing (and rotating the stored refresh token) when it is about to
// expire. It returns ErrSessionNotFound when there is no session or the
// refresh was rejected (the session is then ended).
func (b *BFF) AccessToken(r *http.Request) (string, error) {
	ctx := r.Context()
	token := cookieValue(r, b.cookies.sessionName)
	if token == "" {
		return "", ErrSessionNotFound
	}
	sess, err := b.cfg.Sessions.Get(ctx, token)
	if err != nil {
		return "", err
	}
	if sess.AccessToken != "" && b.now().Add(refreshSkew).Before(sess.AccessTokenExpiresAt) {
		return sess.AccessToken, nil
	}
	if sess.RefreshToken == "" {
		return "", ErrSessionNotFound
	}
	tok, err := b.cfg.Client.Refresh(ctx, sess.RefreshToken)
	if err != nil {
		var re *oauth2.RetrieveError
		if errors.As(err, &re) {
			// invalid_grant: revoked, reused or past its absolute lifetime.
			if derr := b.cfg.Sessions.Delete(ctx, token); derr != nil {
				return "", fmt.Errorf("ending session after rejected refresh: %w", derr)
			}
			return "", ErrSessionNotFound
		}
		return "", err
	}
	sess.AccessToken = tok.AccessToken
	sess.AccessTokenExpiresAt = tok.Expiry
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	if idt, ok := tok.Extra("id_token").(string); ok && idt != "" {
		sess.IDToken = idt
	}
	if err := b.cfg.Sessions.Update(ctx, token, sess); err != nil {
		return "", err
	}
	return sess.AccessToken, nil
}

// --- handlers ---

func (b *BFF) handleSession(w http.ResponseWriter, r *http.Request) {
	sess, p, memberships, err := b.CurrentSession(r)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			b.logger.ErrorContext(r.Context(), "reading session", "error", err)
			writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
			return
		}
		writeJSON(w, http.StatusOK, SessionStatus{Authenticated: false})
		return
	}
	exp := sess.ExpiresAt
	writeJSON(w, http.StatusOK, SessionStatus{
		Authenticated: true,
		UserID:        p.ID,
		ExpiresAt:     &exp,
		User:          toUser(p, memberships),
	})
}

func (b *BFF) handleMe(w http.ResponseWriter, r *http.Request) {
	_, p, memberships, err := b.CurrentSession(r)
	if err != nil {
		if !errors.Is(err, ErrSessionNotFound) {
			b.logger.ErrorContext(r.Context(), "reading session", "error", err)
			writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
			return
		}
		writeAuthError(w, http.StatusUnauthorized, "UNAUTHENTICATED", "authentication required")
		return
	}
	writeJSON(w, http.StatusOK, toUser(p, memberships))
}

func (b *BFF) handlePasswordLogin(w http.ResponseWriter, _ *http.Request) {
	writeAuthError(w, http.StatusNotImplemented, "PASSWORD_LOGIN_UNSUPPORTED",
		"password login is not supported; sign in with SystemAuth via GET "+b.cfg.BasePath+"/auth/login")
}

func (b *BFF) handleLogin(w http.ResponseWriter, r *http.Request) {
	b.startLogin(w, r)
}

// knownProviders are the upstream providers SystemAuth may offer.
var knownProviders = map[string]bool{"github": true, "google": true}

func (b *BFF) handleProviderLogin(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")
	if !knownProviders[provider] {
		writeAuthError(w, http.StatusNotFound, "UNKNOWN_PROVIDER", "unknown login provider")
		return
	}
	b.startLogin(w, r, IDPHint(provider))
}

func (b *BFF) startLogin(w http.ResponseWriter, r *http.Request, opts ...oauth2.AuthCodeOption) {
	ctx := r.Context()
	returnTo := b.cfg.DefaultReturnTo
	if raw := r.URL.Query().Get("return_to"); raw != "" {
		v, err := b.validateReturnTo(raw)
		if err != nil {
			writeAuthError(w, http.StatusBadRequest, "INVALID_RETURN_TO", "return_to is not allowed")
			return
		}
		returnTo = v
	}
	state, err := randomToken()
	if err != nil {
		b.internalError(w, r, "generating login state", err)
		return
	}
	nonce, err := randomToken()
	if err != nil {
		b.internalError(w, r, "generating nonce", err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	if err := b.cfg.LoginStates.Put(ctx, state, LoginState{
		Nonce:     nonce,
		Verifier:  verifier,
		ReturnTo:  returnTo,
		ExpiresAt: b.now().Add(loginStateTTL),
	}); err != nil {
		b.internalError(w, r, "storing login state", err)
		return
	}
	b.cookies.set(w, b.cookies.stateName, state, loginStateTTL)
	//nolint:gosec // G710: redirect target is the discovered SystemAuth authorization endpoint
	http.Redirect(w, r, b.cfg.Client.AuthCodeURL(state, nonce, verifier, opts...), http.StatusFound)
}

func (b *BFF) handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	stateCookie := cookieValue(r, b.cookies.stateName)
	b.cookies.clear(w, b.cookies.stateName)

	if e := q.Get("error"); e != "" {
		writeAuthError(w, http.StatusBadRequest, "LOGIN_FAILED", "login was cancelled or denied: "+e)
		return
	}
	state := q.Get("state")
	if state == "" || stateCookie == "" || subtle.ConstantTimeCompare([]byte(state), []byte(stateCookie)) != 1 {
		writeAuthError(w, http.StatusBadRequest, "INVALID_STATE", "invalid login state")
		return
	}
	ls, err := b.cfg.LoginStates.Take(ctx, state)
	if err != nil {
		if !errors.Is(err, ErrInvalidState) {
			b.internalError(w, r, "reading login state", err)
			return
		}
		writeAuthError(w, http.StatusBadRequest, "INVALID_STATE", "invalid login state")
		return
	}
	code := q.Get("code")
	if code == "" {
		writeAuthError(w, http.StatusBadRequest, "LOGIN_FAILED", "missing authorization code")
		return
	}

	tok, err := b.cfg.Client.Exchange(ctx, code, ls.Verifier)
	if err != nil {
		b.logger.WarnContext(ctx, "SystemAuth code exchange failed", "error", err)
		writeAuthError(w, http.StatusBadGateway, "LOGIN_FAILED", "login failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		b.logger.WarnContext(ctx, "SystemAuth returned no id_token")
		writeAuthError(w, http.StatusBadGateway, "LOGIN_FAILED", "login failed")
		return
	}
	idt, err := b.cfg.Client.VerifyIDToken(ctx, rawID, ls.Nonce)
	if err != nil {
		b.logger.WarnContext(ctx, "ID token rejected", "error", err)
		writeAuthError(w, http.StatusUnauthorized, "LOGIN_FAILED", "login failed")
		return
	}
	var info *UserInfo
	if b.cfg.Client.Metadata().UserinfoEndpoint != "" {
		info, err = b.cfg.Client.UserInfo(ctx, tok.AccessToken)
		if err != nil {
			b.logger.WarnContext(ctx, "SystemAuth userinfo failed", "error", err)
			writeAuthError(w, http.StatusBadGateway, "LOGIN_FAILED", "login failed")
			return
		}
	}
	identity, err := IdentityFromClaims(idt, info)
	if err != nil {
		b.logger.WarnContext(ctx, "userinfo rejected", "error", err)
		writeAuthError(w, http.StatusUnauthorized, "LOGIN_FAILED", "login failed")
		return
	}

	p, err := ResolvePrincipal(ctx, b.cfg.Principals, identity, b.now())
	if err != nil {
		switch {
		case errors.Is(err, ErrEmailNotVerified):
			writeAuthError(w, http.StatusForbidden, "EMAIL_NOT_VERIFIED", "a verified email address is required to sign in")
		case errors.Is(err, ErrEmailConflict):
			writeAuthError(w, http.StatusConflict, "ACCOUNT_CONFLICT", "an account with this email already exists and cannot be linked automatically")
		case errors.Is(err, ErrPrincipalInactive):
			writeAuthError(w, http.StatusForbidden, "ACCOUNT_DISABLED", "account is disabled")
		default:
			b.internalError(w, r, "resolving principal", err)
		}
		return
	}

	if err := b.establishSession(ctx, w, r, p, idt, sessionClaims(idt, info), tok, rawID); err != nil {
		b.internalError(w, r, "creating session", err)
		return
	}
	b.logger.InfoContext(ctx, "login succeeded", "principal_id", p.ID)
	//nolint:gosec // G710: ReturnTo was validated against the allowlist when the login started
	http.Redirect(w, r, ls.ReturnTo, http.StatusFound)
}

// establishSession issues a fresh session token (never reusing one the
// browser presented, to prevent session fixation) and sets the cookie.
func (b *BFF) establishSession(ctx context.Context, w http.ResponseWriter, r *http.Request, p *Principal, idt *IDTokenClaims, claims map[string]any, tok *oauth2.Token, idToken string) error {
	if old := cookieValue(r, b.cookies.sessionName); old != "" {
		if err := b.cfg.Sessions.Delete(ctx, old); err != nil {
			return fmt.Errorf("deleting previous session: %w", err)
		}
	}
	token, err := randomToken()
	if err != nil {
		return err
	}
	now := b.now()
	if err := b.cfg.Sessions.Create(ctx, token, Session{
		PrincipalID:          p.ID,
		Subject:              idt.Subject,
		SID:                  idt.SID,
		Claims:               claims,
		AccessToken:          tok.AccessToken,
		RefreshToken:         tok.RefreshToken,
		IDToken:              idToken,
		AccessTokenExpiresAt: tok.Expiry,
		CreatedAt:            now,
		ExpiresAt:            now.Add(b.cfg.SessionLifetime),
	}); err != nil {
		return err
	}
	b.cookies.set(w, b.cookies.sessionName, token, b.cfg.SessionLifetime)
	return nil
}

// handleLogout serves POST /bff/auth/logout: it deletes the session,
// revokes the SystemAuth refresh token (which revokes its token family)
// and clears the cookie. The SystemAuth login session itself is left alone;
// send the browser to SystemAuth's /logout to end it too.
func (b *BFF) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !b.sameOriginRequest(r) {
		writeAuthError(w, http.StatusForbidden, "CSRF_REJECTED", "cross-origin request rejected")
		return
	}
	if token := cookieValue(r, b.cookies.sessionName); token != "" {
		sess, err := b.cfg.Sessions.Get(ctx, token)
		switch {
		case err == nil:
			if err := b.cfg.Sessions.Delete(ctx, token); err != nil {
				b.internalError(w, r, "deleting session", err)
				return
			}
			b.revokeTokens(ctx, sess)
		case errors.Is(err, ErrSessionNotFound):
		default:
			b.internalError(w, r, "reading session", err)
			return
		}
	}
	b.cookies.clear(w, b.cookies.sessionName)
	w.WriteHeader(http.StatusNoContent)
}

// revokeTokens revokes the session's SystemAuth tokens. Failure is logged,
// not returned: the local session is already gone, and the tokens expire
// on their own.
func (b *BFF) revokeTokens(ctx context.Context, sess Session) {
	token, hint := sess.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = sess.AccessToken, "access_token"
	}
	if token == "" {
		return
	}
	if err := b.cfg.Client.Revoke(ctx, token, hint); err != nil {
		b.logger.WarnContext(ctx, "revoking SystemAuth token on logout", "error", err)
	}
}

func (b *BFF) internalError(w http.ResponseWriter, r *http.Request, msg string, err error) {
	b.logger.ErrorContext(r.Context(), msg, "error", err)
	writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
}

// --- CSRF and redirects ---

func isUnsafeMethod(m string) bool {
	return m != http.MethodGet && m != http.MethodHead && m != http.MethodOptions
}

// sameOriginRequest is the CSRF check for state-changing BFF requests: a
// browser-sent Origin (or Referer) must be an allowed origin, and the body
// must be JSON (which a cross-site HTML form cannot send without a CORS
// preflight). The session cookie is also SameSite=Lax.
func (b *BFF) sameOriginRequest(r *http.Request) bool {
	origin := ""
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		origin = o
	} else if ref := r.Header.Get("Referer"); ref != "" {
		origin = ref
	}
	if origin != "" {
		o, err := parseOrigin(origin)
		if err != nil || !b.origins[o] {
			return false
		}
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && ct == "application/json"
}

// validateReturnTo accepts a same-origin absolute path or an absolute URL
// on an allowed origin.
func (b *BFF) validateReturnTo(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\\\t\r\n") {
		return "", errors.New("return_to not allowed")
	}
	for _, c := range raw {
		if c < 0x20 || c == 0x7f {
			return "", errors.New("return_to not allowed")
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil {
		return "", errors.New("return_to not allowed")
	}
	if u.Scheme == "" && u.Host == "" {
		if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
			return "", errors.New("return_to not allowed")
		}
		return u.String(), nil
	}
	origin, err := parseOrigin(raw)
	if err != nil || !b.origins[origin] {
		return "", errors.New("return_to not allowed")
	}
	return u.String(), nil
}

// parseOrigin normalizes an absolute http(s) URL to scheme://host[:port].
func parseOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("relyingparty: invalid origin %q: %w", raw, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "https" && scheme != "http") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("relyingparty: invalid origin %q: must be an absolute http(s) URL", raw)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}

// --- cookies ---

type rpCookies struct {
	sessionName string
	stateName   string
	secure      bool
}

func newRPCookies(insecure bool) rpCookies {
	if insecure {
		return rpCookies{sessionName: insecureSessionCookieName, stateName: insecureStateCookieName}
	}
	return rpCookies{sessionName: SessionCookieName, stateName: stateCookieName, secure: true}
}

// cookie builds a host-only, HttpOnly, Path=/ cookie. SameSite=Lax lets the
// session accompany the top-level redirect back from SystemAuth.
func (c rpCookies) cookie(name, value string, maxAge int) *http.Cookie {
	//nolint:gosec // G124: HttpOnly and SameSite=Lax always; Secure unless InsecureCookies was set for local HTTP
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	}
}

func (c rpCookies) set(w http.ResponseWriter, name, value string, lifetime time.Duration) {
	http.SetCookie(w, c.cookie(name, value, int(lifetime.Seconds())))
}

func (c rpCookies) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, c.cookie(name, "", -1))
}

func cookieValue(r *http.Request, name string) string {
	ck, err := r.Cookie(name)
	if err != nil {
		// http.ErrNoCookie is the only error r.Cookie returns.
		return ""
	}
	return ck.Value
}
