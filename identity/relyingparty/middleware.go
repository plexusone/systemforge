package relyingparty

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AuthMethod is how a request was authenticated.
type AuthMethod string

const (
	// AuthMethodSession is a BFF cookie session.
	AuthMethodSession AuthMethod = "session"
	// AuthMethodAccessToken is a SystemAuth JWT access token.
	AuthMethodAccessToken AuthMethod = "access_token"
)

// AuthenticatedPrincipal is the principal of an authenticated request.
type AuthenticatedPrincipal struct {
	// ID is the app-local principal ID (for a client-credentials token
	// without a local principal, the OAuth client ID).
	ID string
	// Type is the principal type: human, service, ... or "client" for a
	// client-credentials token.
	Type string
	// Subject is the SystemAuth subject (sf_principal_id), when known.
	Subject string
	// Method is how the request authenticated.
	Method AuthMethod
	// Scopes are the access token's scopes (empty for sessions, which
	// carry the principal's full access).
	Scopes []string
	// Memberships are the principal's organization memberships.
	Memberships []Membership
}

// HasScope reports whether the principal's credential carries scope.
// Session principals have no scopes and always return false.
func (p *AuthenticatedPrincipal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type principalKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *AuthenticatedPrincipal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFromContext returns the authenticated principal, if any.
func PrincipalFromContext(ctx context.Context) (*AuthenticatedPrincipal, bool) {
	p, ok := ctx.Value(principalKey{}).(*AuthenticatedPrincipal)
	return p, ok && p != nil
}

// AccessTokenVerifier verifies JWT access tokens. *Client implements it.
type AccessTokenVerifier interface {
	VerifyAccessToken(ctx context.Context, raw string) (*AccessTokenClaims, error)
}

// BearerConfig configures BearerMiddleware.
type BearerConfig struct {
	// Tokens verifies SystemAuth JWT access tokens. Nil disables them.
	Tokens AccessTokenVerifier

	// Principals resolves token subjects to app-local principals
	// (required).
	Principals PrincipalStore

	// Memberships supplies organization memberships. Default:
	// ClaimsMemberships, which reads a JWT access token's claims.
	Memberships MembershipSource

	// Sessions, when set, also accepts a BFF cookie session for requests
	// without credentials, so one middleware protects an API used by both
	// the browser and programmatic clients.
	Sessions *BFF

	// AllowClientTokens accepts client-credentials access tokens (subject
	// equal to the client ID, no local principal) as a "client" principal.
	AllowClientTokens bool

	// ServicePrincipals accepts SystemAuth service accounts: a verified
	// access token whose subject has no local principal and whose
	// principal_type claim is "service" creates one with
	// PrincipalStore.CreatePrincipal (VerifiedIdentity.Service), since a
	// service account never signs in. The principal store must support
	// service identities. Without it such a token is refused as an unknown
	// principal.
	ServicePrincipals bool

	// Revocation, when set, refuses a JWT access token issued before a
	// recorded change to its principal's access (ADR-010). The refusal is
	// a 401 invalid_token "token expired", which makes the client refresh
	// and obtain claims that reflect the change.
	Revocation *RevocationCache

	// Organization names the organization a request addresses, so that a
	// change to the principal's access in another organization does not
	// refuse it. Without it every change to the principal applies.
	Organization func(r *http.Request) string

	// DPoP verifies the proofs that come with DPoP-bound access tokens (a
	// cnf.jkt claim), presented with the "DPoP" authorization scheme (RFC
	// 9449). SystemAuth binds every token it issues unless the client is a
	// legacy bearer exception, so DPoP is required whenever Tokens is set,
	// unless AllowBearerTokens is. A DPoP-bound token presented with the
	// Bearer scheme is always refused, so a stolen bound token does not
	// work as a bearer token.
	DPoP *DPoPConfig

	// AllowBearerTokens also accepts unbound JWT access tokens with the
	// Bearer scheme, as SystemAuth issues to clients registered with its
	// allow_bearer_tokens exception. It is an explicit opt-in: by default
	// an access token without cnf.jkt is refused, since whoever holds a
	// bearer token can use it.
	AllowBearerTokens bool

	// Logger receives storage errors. Default: slog.Default().
	Logger *slog.Logger
}

// BearerMiddleware authenticates programmatic clients and puts an
// AuthenticatedPrincipal in the request context. It accepts, in order:
//
//   - Authorization: DPoP <JWT> with a DPoP header — a SystemAuth JWT access
//     token bound to a DPoP key, verified against the SystemAuth JWKS, and
//     a proof signed by that key for this request; its sub must be linked
//     to a local principal (sf_principal_id), who must have signed in to
//     the app once.
//   - Authorization: Bearer <JWT>, only with AllowBearerTokens — an unbound
//     SystemAuth JWT access token, checked the same way.
//   - a BFF session cookie, when Sessions is set.
//
// Anything else gets 401 with WWW-Authenticate challenges for the DPoP
// scheme and, for legacy tokens, the Bearer scheme. Static API keys are
// not accepted (ADR-016): command-line tools sign people in with
// identity/publicclient, and automation uses service accounts.
//
// It panics without Principals, and when Tokens is set without DPoP or
// AllowBearerTokens, since it could then accept no access token.
func BearerMiddleware(cfg BearerConfig) func(http.Handler) http.Handler {
	dv := cfg.mustVerifier()
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	cfg.Memberships = defaultMembershipSource(cfg.Memberships)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := cfg.authenticate(r, dv)
			if err != nil {
				var authErr *bearerError
				if !errors.As(err, &authErr) {
					logger.ErrorContext(r.Context(), "authenticating request", "error", err)
					writeAuthError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
					return
				}
				if authErr.status == http.StatusForbidden {
					writeAuthError(w, http.StatusForbidden, "CSRF_REJECTED", authErr.message)
					return
				}
				for _, c := range authErr.challenges(dv != nil) {
					w.Header().Add("WWW-Authenticate", c)
				}
				writeAuthError(w, http.StatusUnauthorized, "UNAUTHENTICATED", authErr.message)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// mustVerifier checks cfg and returns its DPoP proof verifier, nil when
// DPoP is not configured.
func (cfg BearerConfig) mustVerifier() *dpopVerifier {
	if cfg.Principals == nil {
		panic("relyingparty: BearerConfig.Principals is required")
	}
	if cfg.Tokens != nil && cfg.DPoP == nil && !cfg.AllowBearerTokens {
		panic("relyingparty: BearerConfig.DPoP is required to accept SystemAuth access tokens, which are DPoP-bound (set AllowBearerTokens to accept only unbound legacy tokens)")
	}
	if cfg.DPoP == nil {
		return nil
	}
	return newDPoPVerifier(cfg.DPoP)
}

// bearerError is an authentication failure reported to the client.
type bearerError struct {
	code    string
	message string
	// description is sent as error_description in the challenge, when set.
	description string
	// status overrides the 401 the client is sent.
	status int
	// dpop marks a failure of a DPoP request, reported in the DPoP
	// challenge rather than the Bearer one (RFC 9449 §7.1).
	dpop bool
}

func (e *bearerError) Error() string { return e.message }

// challenges are the WWW-Authenticate challenges for the failure: the
// error goes on the DPoP challenge for a DPoP request and on the Bearer
// one otherwise; the DPoP challenge is offered when DPoP is configured.
func (e *bearerError) challenges(dpopOn bool) []string {
	if e.dpop {
		return []string{dpopChallenge + e.challengeParams()}
	}
	out := []string{bearerChallenge + e.challengeParams()}
	if dpopOn {
		out = append(out, dpopChallenge)
	}
	return out
}

// challengeParams is the error and error_description parameters of the
// WWW-Authenticate challenge (RFC 6750 section 3).
func (e *bearerError) challengeParams() string {
	var out string
	if e.code != "" {
		out += `, error="` + e.code + `"`
	}
	if e.description != "" {
		out += `, error_description="` + e.description + `"`
	}
	return out
}

// errNoCredentials is the failure for a request that carries no
// credentials at all (as opposed to invalid ones).
var errNoCredentials error = &bearerError{message: "authentication required"}

func errUnauthenticated(code, message string) error {
	return &bearerError{code: code, message: message}
}

func (cfg BearerConfig) authenticate(r *http.Request, dv *dpopVerifier) (*AuthenticatedPrincipal, error) {
	ctx := r.Context()
	token := ""
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, value, ok := strings.Cut(auth, " ")
		if ok && dv != nil && strings.EqualFold(scheme, "DPoP") {
			p, err := cfg.authenticateDPoP(r, dv, strings.TrimSpace(value))
			var authErr *bearerError
			if errors.As(err, &authErr) {
				authErr.dpop = true
			}
			return p, err
		}
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return nil, errUnauthenticated("invalid_request", "unsupported authorization scheme")
		}
		token = strings.TrimSpace(value)
	}
	org := ""
	if cfg.Organization != nil {
		org = cfg.Organization(r)
	}

	if token == "" {
		if cfg.Sessions != nil {
			p, err := cfg.Sessions.authenticate(r)
			if err == nil {
				// A browser attaches the cookie to cross-site requests on
				// its own, so state-changing ones must prove they come
				// from an allowed origin, as RequireSession demands.
				if isUnsafeMethod(r.Method) && !cfg.Sessions.sameOriginRequest(r) {
					return nil, &bearerError{message: "cross-origin request rejected", status: http.StatusForbidden}
				}
				return p, nil
			}
			if !errors.Is(err, ErrSessionNotFound) {
				return nil, err
			}
		}
		return nil, errNoCredentials
	}

	if strings.Count(token, ".") != 2 {
		return nil, errUnauthenticated("invalid_token", "invalid access token")
	}
	claims, err := cfg.verifyJWT(ctx, token)
	if err != nil {
		return nil, err
	}
	if claims.DPoPThumbprint() != "" {
		return nil, errUnauthenticated("invalid_token", "DPoP-bound token requires the DPoP scheme and a DPoP proof")
	}
	if !cfg.AllowBearerTokens {
		return nil, errUnauthenticated("invalid_token", "access token is not DPoP-bound; bearer tokens are not accepted")
	}
	return cfg.principalForJWT(ctx, token, claims, org)
}

// authenticateDPoP authenticates "Authorization: DPoP <token>": the token
// must be DPoP-bound and the request must carry a valid proof signed by
// the key it is bound to.
func (cfg BearerConfig) authenticateDPoP(r *http.Request, dv *dpopVerifier, token string) (*AuthenticatedPrincipal, error) {
	ctx := r.Context()
	if strings.Count(token, ".") != 2 {
		return nil, errUnauthenticated("invalid_token", "invalid access token")
	}
	claims, err := cfg.verifyJWT(ctx, token)
	if err != nil {
		return nil, err
	}
	jkt := claims.DPoPThumbprint()
	if jkt == "" {
		return nil, errUnauthenticated("invalid_token", "token presented with the DPoP scheme is not DPoP-bound")
	}
	if err := dv.verify(r, token, jkt); err != nil {
		return nil, err
	}
	org := ""
	if cfg.Organization != nil {
		org = cfg.Organization(r)
	}
	return cfg.principalForJWT(ctx, token, claims, org)
}

func (cfg BearerConfig) verifyJWT(ctx context.Context, token string) (*AccessTokenClaims, error) {
	if cfg.Tokens == nil {
		return nil, errUnauthenticated("invalid_token", "access tokens are not accepted")
	}
	claims, err := cfg.Tokens.VerifyAccessToken(ctx, token)
	if err != nil {
		return nil, errUnauthenticated("invalid_token", "invalid access token")
	}
	return claims, nil
}

func (cfg BearerConfig) principalForJWT(ctx context.Context, token string, claims *AccessTokenClaims, org string) (*AuthenticatedPrincipal, error) {
	if cfg.Revocation != nil {
		var iat time.Time
		if claims.IssuedAt != nil {
			iat = claims.IssuedAt.Time
		}
		if !cfg.Revocation.Accept(claims.Subject, org, iat) {
			return nil, &bearerError{code: "invalid_token", message: "token expired", description: "token expired"}
		}
	}
	p, err := cfg.Principals.FindBySubject(ctx, claims.Subject)
	if errors.Is(err, ErrPrincipalNotFound) && cfg.ServicePrincipals && isServiceToken(claims) {
		p, err = cfg.provisionService(ctx, claims)
	}
	if errors.Is(err, ErrPrincipalNotFound) {
		if cfg.AllowClientTokens && claims.ClientID != "" && claims.Subject == claims.ClientID {
			return &AuthenticatedPrincipal{
				ID:      claims.ClientID,
				Type:    "client",
				Subject: claims.Subject,
				Method:  AuthMethodAccessToken,
				Scopes:  claims.Scopes,
			}, nil
		}
		return nil, errUnauthenticated("invalid_token", "unknown principal; sign in to the application first")
	}
	if err != nil {
		return nil, err
	}
	if isServiceToken(claims) && p.Type != "service" {
		// SystemAuth says the subject is a service account; a local
		// principal of another type is never that account.
		return nil, errUnauthenticated("invalid_token", "the token's subject is not a service account")
	}
	if !p.Active {
		return nil, errUnauthenticated("invalid_token", "principal is inactive")
	}
	memberships, err := cfg.Memberships.Memberships(ctx, MembershipQuery{
		Principal: p, Subject: claims.Subject, Claims: claims.Raw,
		AccessToken: func(context.Context) (string, error) { return token, nil },
	})
	if err != nil {
		return nil, err
	}
	return &AuthenticatedPrincipal{
		ID:          p.ID,
		Type:        principalType(p),
		Subject:     claims.Subject,
		Method:      AuthMethodAccessToken,
		Scopes:      claims.Scopes,
		Memberships: memberships,
	}, nil
}

func principalType(p *Principal) string {
	if p.Type == "" {
		return "human"
	}
	return p.Type
}

// PrincipalTypeClaim is the access token claim naming the principal's type;
// SystemAuth sets it to "service" for a service account.
const PrincipalTypeClaim = "principal_type"

// ServiceAccountClientID is the client_id of the tokens SystemAuth issues to
// service accounts through the JWT-bearer grant. An API that accepts service
// accounts lists it in Config.AcceptedClientIDs.
const ServiceAccountClientID = "systemauth-jwt-bearer" //nolint:gosec // G101: a public client identifier, not a credential

func isServiceToken(claims *AccessTokenClaims) bool {
	t, ok := claims.Raw[PrincipalTypeClaim].(string)
	return ok && t == "service"
}

// provisionService creates the local principal of a service account on its
// first request. A concurrent request may create it first; the principal it
// created is used. Either way the principal must be of type service: a
// store that ignores VerifiedIdentity.Service would otherwise turn a service
// account into a person.
func (cfg BearerConfig) provisionService(ctx context.Context, claims *AccessTokenClaims) (*Principal, error) {
	name, _ := claims.Raw["name"].(string) // optional: a service account may carry no name
	p, err := cfg.Principals.CreatePrincipal(ctx, VerifiedIdentity{Subject: claims.Subject, Name: name, Service: true})
	if errors.Is(err, ErrSubjectLinked) {
		p, err = cfg.Principals.FindBySubject(ctx, claims.Subject)
		if err != nil {
			return nil, err
		}
		if p.Type != "service" {
			return nil, errUnauthenticated("invalid_token", "the token's subject is not a service account")
		}
		return p, nil
	}
	if err != nil {
		return nil, fmt.Errorf("relyingparty: creating the service principal: %w", err)
	}
	if p.Type != "service" {
		return nil, fmt.Errorf("relyingparty: the principal store created a %q principal for a service identity; it must support VerifiedIdentity.Service before ServicePrincipals is enabled", p.Type)
	}
	return p, nil
}
