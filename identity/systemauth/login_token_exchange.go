package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// LoginTokenPath exchanges a managed principal's login token for a
// SystemAuth login session (ADR-005).
const LoginTokenPath = "/login-token"

// ManagedClaim is the ID token and userinfo claim, true for managed
// principals: humans with at least one active manager (ADR-009), with or
// without an email. It is absent for everyone else.
const ManagedClaim = "managed"

// loginTokenProvider is recorded as the provider of sessions established
// with a login token.
const loginTokenProvider = "login_token"

// Default login token exchange rate limits. A classroom signs in at once
// from one address, so the per-address limit allows a class-sized burst;
// the per-client limit bounds every address together.
var (
	DefaultLoginTokenAddressLimit = ratelimit.PerMinute(60)
	DefaultLoginTokenClientLimit  = ratelimit.PerMinute(600)
)

// errLoginTokenRejected is the single failure of the exchange; the
// response never says why.
var errLoginTokenRejected = errors.New("invalid login token")

// loginTokenExchange holds the dependencies of the exchange endpoint.
type loginTokenExchange struct {
	credentials  credential.Service
	allowed      func(ctx context.Context, clientID string) (bool, error)
	knownClient  func(ctx context.Context, clientID string) bool
	clientIP     func(r *http.Request) string
	rates        ratelimit.Storage
	addressLimit ratelimit.Limit
	clientLimit  ratelimit.Limit
}

// WithCredentialService sets the credential service that verifies login
// tokens. Defaults to one over the Ent database when the server uses
// EntStorage; without either, the login token endpoint is not mounted.
func WithCredentialService(svc credential.Service) Option {
	return func(s *Server) { s.socialOpts.credentials = svc }
}

// WithLoginTokenRateLimit sets the rate limit storage and the limits per
// source address and per client for the login token endpoint. Defaults to
// in-memory storage with DefaultLoginTokenAddressLimit and
// DefaultLoginTokenClientLimit; use shared storage, such as Redis, when
// several instances serve the endpoint.
func WithLoginTokenRateLimit(storage ratelimit.Storage, perAddress, perClient ratelimit.Limit) Option {
	return func(s *Server) {
		s.socialOpts.loginTokenRate = storage
		s.socialOpts.loginTokenIP = perAddress
		s.socialOpts.loginTokenCli = perClient
	}
}

// WithLoginTokenClientIP sets how the login token endpoint finds the
// client's address, for its per-address rate limit and the last-used
// address recorded on the token. The JWT-bearer grant records the same
// address as a service account key's last use. The default is the direct
// peer, which
// behind a reverse proxy is the proxy: pass
// ratelimit.ForwardedClientIP(proxyNetworks...) there. Never read
// forwarding headers without naming the proxies that set them.
func WithLoginTokenClientIP(clientIP func(r *http.Request) string) Option {
	return func(s *Server) { s.socialOpts.loginTokenClientIP = clientIP }
}

// setupLoginTokens enables the exchange when managed principals are on and
// a credential service is available.
func (sl *socialLogin) setupLoginTokens(s *Server) {
	if !s.managedPrincipalsEnabled() {
		return
	}
	creds := s.socialOpts.credentials
	if creds == nil {
		if es, ok := s.storage.(*EntStorage); ok {
			creds = credential.NewService(es.db)
		}
	}
	if creds == nil {
		s.logger.Warn("managed principals enabled without a credential service; the login token endpoint is not mounted")
		return
	}
	x := &loginTokenExchange{
		credentials: creds,
		allowed:     s.ManagedPrincipalsAllowed,
		clientIP:    s.socialOpts.loginTokenClientIP,
		knownClient: func(ctx context.Context, clientID string) bool {
			_, err := s.storage.GetClientByID(ctx, clientID)
			return err == nil
		},
		rates:        s.socialOpts.loginTokenRate,
		addressLimit: s.socialOpts.loginTokenIP,
		clientLimit:  s.socialOpts.loginTokenCli,
	}
	if x.clientIP == nil {
		x.clientIP = ratelimit.PeerIP
	}
	if x.rates == nil {
		s.logger.Warn("login token endpoint using in-memory rate limits; limits are not shared between instances")
		x.rates = ratelimit.NewMemoryStorage()
	}
	if x.addressLimit.Rate <= 0 {
		x.addressLimit = DefaultLoginTokenAddressLimit
	}
	if x.clientLimit.Rate <= 0 {
		x.clientLimit = DefaultLoginTokenClientLimit
	}
	sl.loginTokens = x
}

// handleLoginToken exchanges a login token for a login session. It takes
// the form fields token, client_id, and optionally return_to, and
// redirects to return_to or the default target. The form must be posted
// from a page on the issuer's origin or an allowed redirect origin
// (Origin/Referer check), or it is refused with 403. Unknown, malformed,
// expired, revoked, and used tokens, a client that does not allow managed
// principals, and a principal that is inactive or not managed all receive
// the same response.
func (sl *socialLogin) handleLoginToken(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	x := sl.loginTokens

	// The exchange replaces the browser's login session, so a cross-site
	// form must not be able to sign a visitor in as someone else.
	if !sl.redirects.fromTrustedOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	clientID := r.PostForm.Get("client_id")
	plain := r.PostForm.Get("token")
	returnTo := r.PostForm.Get("return_to")

	address := x.clientIP(r)
	if address == "" {
		address = "unknown"
	}
	// The client key is attacker-chosen, so only registered clients get
	// their own bucket; everything else shares one rather than growing the
	// limiter without bound.
	clientBucket := "unknown"
	if clientID != "" && len(clientID) <= 256 && x.knownClient(ctx, clientID) {
		clientBucket = clientID
	}
	for _, check := range []struct {
		key   string
		limit ratelimit.Limit
	}{
		{"login_token:ip:" + address, x.addressLimit},
		{"login_token:client:" + clientBucket, x.clientLimit},
	} {
		res, err := x.rates.Allow(ctx, check.key, check.limit)
		if errors.Is(err, ratelimit.ErrTooManyKeys) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		if err != nil {
			logger.Error("login token rate limit", "error", err)
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		if !res.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(int(res.RetryAfter.Seconds())+1))
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
	}

	target := sl.redirects.defaultTarget
	if returnTo != "" {
		t, err := sl.redirects.resolve(returnTo)
		if err != nil {
			http.Error(w, "invalid return_to", http.StatusBadRequest)
			return
		}
		target = t
	}

	principalID, err := sl.verifyLoginToken(ctx, x, clientID, plain, address)
	if errors.Is(err, errLoginTokenRejected) {
		logger.Info("login token rejected", "client_id", clientID)
		http.Error(w, errLoginTokenRejected.Error(), http.StatusUnauthorized)
		return
	}
	if err != nil {
		logger.Error("login token exchange", "client_id", clientID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := sl.establishSession(ctx, w, r, principalID, loginTokenProvider); err != nil {
		logger.Error("creating login session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("login token sign-in succeeded", "client_id", clientID, "principal_id", principalID)
	//nolint:gosec // G710: target is the default or a return_to resolved against the redirect allowlist
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// verifyLoginToken returns the managed principal a usable token signs in,
// or errLoginTokenRejected.
func (sl *socialLogin) verifyLoginToken(ctx context.Context, x *loginTokenExchange, clientID, plain, ip string) (uuid.UUID, error) {
	if clientID == "" || plain == "" {
		return uuid.Nil, errLoginTokenRejected
	}
	ok, err := x.allowed(ctx, clientID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("checking client: %w", err)
	}
	if !ok {
		return uuid.Nil, errLoginTokenRejected
	}
	cred, err := x.credentials.VerifyLoginToken(ctx, plain, ip)
	if errors.Is(err, credential.ErrInvalidLoginToken) {
		return uuid.Nil, errLoginTokenRejected
	}
	if err != nil {
		return uuid.Nil, err
	}
	p, err := sl.directory.GetPrincipal(ctx, cred.PrincipalID)
	if errors.Is(err, ErrPrincipalNotFound) {
		return uuid.Nil, errLoginTokenRejected
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("loading principal: %w", err)
	}
	// Only managed principals sign in with login tokens. Having an email
	// does not matter, but management that has ended (Release) does: the
	// principal then uses its own credentials.
	if !p.Active || !p.Managed {
		return uuid.Nil, errLoginTokenRejected
	}
	return p.ID, nil
}
