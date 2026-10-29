package systemauth

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/plexusone/systemforge/session/clientaddr"
	"github.com/plexusone/systemforge/session/ratelimit"
)

// RateLimitConfig configures SystemAuth's rate limits (see
// session/ratelimit): a default limit per client address on every route,
// route policies for the token, login and sign-up paths, a limit for
// signed-in callers, and limits inside the handlers that need a request's
// outcome. The zero value turns them all on with the defaults.
type RateLimitConfig struct {
	// Disabled turns off the default layer and the route policies, for a
	// host that applies its own ratelimit.Policy in front of SystemAuth.
	// The handler limits stay on.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty" jsonschema:"default=false,description=Turn off the default and route rate limits (handler limits stay on)"`

	// RedisURL is a Redis URL (redis://user:pass@host:6379/0) of the
	// storage every instance shares. The packaged service (systemauthsvc)
	// connects to it; an embedding application passes
	// WithRateLimitStorage instead. Empty keeps the counters in memory,
	// which suits a single instance. Supports environment variable
	// expansion: ${SYSTEMAUTH_RATE_LIMIT_REDIS_URL}.
	RedisURL string `json:"redis_url,omitempty" yaml:"redis_url,omitempty" jsonschema:"description=Redis URL of the rate limit storage shared by every instance (supports env var expansion)"`

	// SingleInstance declares that one instance serves SystemAuth, so
	// in-memory counters see every request. dpop.single_instance declares
	// the same. Without either, or a shared storage, the packaged service
	// warns in production: each instance would allow the full limit.
	SingleInstance bool `json:"single_instance,omitempty" yaml:"single_instance,omitempty" jsonschema:"default=false,description=One instance serves SystemAuth, so in-memory rate limit counters are enough"`

	// Default is the limit per client address on every route. Default:
	// 300 requests a minute.
	Default *RateLimitRule `json:"default,omitempty" yaml:"default,omitempty" jsonschema:"description=Limit per client address on every route (default 300 per minute)"`

	// SignedIn is the limit per signed-in principal or service account on
	// the routes that authenticate one. Default: 1200 requests a minute.
	SignedIn *RateLimitRule `json:"signed_in,omitempty" yaml:"signed_in,omitempty" jsonschema:"description=Limit per signed-in principal or service account (default 1200 per minute)"`

	// ExemptNetworks are client networks exempt from every limit:
	// back-channel callers such as relying parties' servers.
	ExemptNetworks []string `json:"exempt_networks,omitempty" yaml:"exempt_networks,omitempty" jsonschema:"description=Client networks (CIDR or single addresses) exempt from rate limits, such as relying parties' servers"`

	// Routes replace the default route policies of the same name (token,
	// login, signup, bff_auth, health, static, payment_webhook) or add
	// new ones.
	Routes []RateLimitRouteConfig `json:"routes,omitempty" yaml:"routes,omitempty" jsonschema:"description=Route policies replacing the defaults of the same name or adding new ones"`
}

// RateLimitRule is a number of requests in a period.
type RateLimitRule struct {
	Requests int      `json:"requests" yaml:"requests" jsonschema:"required,minimum=1,description=Requests allowed in each period"`
	Period   Duration `json:"period" yaml:"period" jsonschema:"required,description=Length of the period (e.g. 1m)"`
}

func (r *RateLimitRule) limit() ratelimit.Limit {
	if r == nil {
		return ratelimit.Limit{}
	}
	return ratelimit.Limit{Rate: r.Requests, Period: r.Period.Duration(), Burst: r.Requests}
}

func (r *RateLimitRule) validate(name string) error {
	if r != nil && (r.Requests <= 0 || r.Period.Duration() <= 0) {
		return fmt.Errorf("%w: rate_limit.%s needs requests and a period above zero", ErrInvalidConfig, name)
	}
	return nil
}

// RateLimitRouteConfig is a route policy (ratelimit.Route).
type RateLimitRouteConfig struct {
	Name       string         `json:"name" yaml:"name" jsonschema:"required,description=Policy name; a default's name replaces it"`
	Paths      []string       `json:"paths" yaml:"paths" jsonschema:"required,description=Paths: exact or ending in * for a prefix"`
	Methods    []string       `json:"methods,omitempty" yaml:"methods,omitempty" jsonschema:"description=Methods the policy covers (default all)"`
	Exempt     bool           `json:"exempt,omitempty" yaml:"exempt,omitempty" jsonschema:"description=Exempt the paths from address limits"`
	PerAddress *RateLimitRule `json:"per_address,omitempty" yaml:"per_address,omitempty" jsonschema:"description=Limit per client address"`
	PerClient  *RateLimitRule `json:"per_client,omitempty" yaml:"per_client,omitempty" jsonschema:"description=Limit per OAuth client"`
	FailOpen   bool           `json:"fail_open,omitempty" yaml:"fail_open,omitempty" jsonschema:"description=Let requests through when the storage fails (routes refuse by default)"`
}

func (c RateLimitRouteConfig) route() ratelimit.Route {
	rt := ratelimit.Route{Name: c.Name, Paths: c.Paths, Methods: c.Methods, Exempt: c.Exempt, FailOpen: c.FailOpen}
	if c.PerAddress != nil {
		rt.Limits = append(rt.Limits, ratelimit.RouteLimit{Key: ratelimit.KeyAddress, Limit: c.PerAddress.limit()})
	}
	if c.PerClient != nil {
		rt.Limits = append(rt.Limits, ratelimit.RouteLimit{Key: ratelimit.KeyClient, Limit: c.PerClient.limit()})
	}
	return rt
}

func (c *RateLimitConfig) validate() error {
	if err := c.Default.validate("default"); err != nil {
		return err
	}
	if err := c.SignedIn.validate("signed_in"); err != nil {
		return err
	}
	if _, err := clientaddr.ParseNetworks(c.ExemptNetworks); err != nil {
		return fmt.Errorf("%w: rate_limit.exempt_networks: %v", ErrInvalidConfig, err)
	}
	for _, rt := range c.Routes {
		if err := rt.PerAddress.validate("routes.per_address"); err != nil {
			return err
		}
		if err := rt.PerClient.validate("routes.per_client"); err != nil {
			return err
		}
	}
	return nil
}

// routes is the effective route table.
func (c *RateLimitConfig) routes() []ratelimit.Route {
	overrides := make([]ratelimit.Route, 0, len(c.Routes))
	for _, rt := range c.Routes {
		overrides = append(overrides, rt.route())
	}
	return ratelimit.MergeRoutes(ratelimit.DefaultRoutes(), overrides...)
}

// Handler limits: checked inside SystemAuth's handlers, on the same
// storage as the layers, because they need the request's outcome or a key
// only the handler knows.
var (
	// DefaultSocialLoginLimit bounds the starts of upstream sign-ins, and
	// separately the callbacks, per client address.
	DefaultSocialLoginLimit = ratelimit.PerMinute(30)

	// DefaultClientAuthFailureLimit bounds failed client authentications
	// at the token endpoint per client address and client; once reached,
	// the pair is refused until the window ends.
	DefaultClientAuthFailureLimit = ratelimit.PerMinute(20)

	// DefaultAddressAuthFailureLimit bounds failed client authentications
	// per client address, whatever the client.
	DefaultAddressAuthFailureLimit = ratelimit.PerMinute(60)

	// DefaultJWTBearerAccountLimit bounds the tokens the JWT-bearer grant
	// issues per service account.
	DefaultJWTBearerAccountLimit = ratelimit.PerMinute(60)
)

// WithRateLimitStorage sets the storage of every rate limit SystemAuth
// applies: the layers, the handler limits, and the login-token limits
// unless WithLoginTokenRateLimit names another. Use shared storage, such as
// ratelimit.RedisStorage, when several instances serve SystemAuth. Default:
// in-memory storage, which suits one instance.
func WithRateLimitStorage(storage ratelimit.Storage) Option {
	return func(s *Server) { s.rates = storage }
}

// RateLimitStorage returns the storage of SystemAuth's rate limits, for a
// host's own handler limits.
func (s *Server) RateLimitStorage() ratelimit.Storage { return s.rates }

// RateLimitPolicy returns the default layer and route policies SystemAuth
// applies, or nil when rate_limit.disabled is set.
func (s *Server) RateLimitPolicy() *ratelimit.Policy { return s.ratePolicy }

// SignedInRateLimit returns middleware applying the limit per signed-in
// principal or service account (rate_limit.signed_in), for routes that
// authenticate one; install it after the authentication middleware.
// Anonymous requests pass.
func (s *Server) SignedInRateLimit() func(http.Handler) http.Handler {
	return s.signedIn.Middleware()
}

// setupRateLimits builds the shared storage, the layers and the signed-in
// limiter.
func (s *Server) setupRateLimits() error {
	cfg := &s.config.RateLimit
	if s.rates == nil {
		s.rates = ratelimit.NewMemoryStorage()
	}
	s.signedIn = ratelimit.NewSignedInLimiter(s.rates, cfg.SignedIn.limit(), ratelimit.WithLogger(s.logger),
		ratelimit.WithObservability(s.observability))
	if cfg.Disabled {
		return nil
	}
	p, err := ratelimit.NewPolicy(ratelimit.PolicyConfig{
		Storage:        s.rates,
		Address:        s.clientAddr,
		Default:        cfg.Default.limit(),
		Routes:         cfg.routes(),
		ExemptNetworks: cfg.ExemptNetworks,
		KnownClient: func(ctx context.Context, id string) bool {
			_, err := s.storage.GetClientByID(ctx, id)
			return err == nil
		},
		Logger:        s.logger,
		Observability: s.observability,
	})
	if err != nil {
		return fmt.Errorf("%w: rate_limit: %v", ErrInvalidConfig, err)
	}
	s.ratePolicy = p
	return nil
}

// rateLimitLayers is the router middleware applying the layers.
func (s *Server) rateLimitLayers(next http.Handler) http.Handler {
	if s.ratePolicy == nil {
		return next
	}
	return s.ratePolicy.Middleware()(next)
}

// limitRequest checks a handler limit keyed by the client address, failing
// closed. It returns false when it answered the request.
func (s *Server) limitRequest(w http.ResponseWriter, r *http.Request, name string, limit ratelimit.Limit) bool {
	address := s.clientIP(r)
	if address == "" {
		address = "unknown"
	}
	return ratelimit.Check(w, r, s.rates, name, "ip:"+address, limit, false, LoggerFromContext(r.Context())) == ratelimit.Allowed
}

// tokenOutcomeLimits applies, at the token endpoint, the limits that count
// outcomes: failed client authentication per address and client, and the
// tokens the JWT-bearer grant issues per service account. A key whose
// limit is used up is refused before the request is handled; the outcome
// is counted after.
func (s *Server) tokenOutcomeLimits(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/token" || r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		logger := LoggerFromContext(ctx)
		address := s.clientIP(r)
		if address == "" {
			address = "unknown"
		}
		form := ratelimit.PeekForm(r)
		client := ratelimit.RequestClientID(r)
		if client == "" || len(client) > 256 {
			client = "unknown"
		}
		failures := []outcomeLimit{
			{"client_auth_failures", "ip:" + address, DefaultAddressAuthFailureLimit},
			{"client_auth_failures", "ip:" + address + ":client:" + client, DefaultClientAuthFailureLimit},
		}
		var issued []outcomeLimit
		if s.jwtBearerEnabled() && form.Get("grant_type") == GrantTypeJWTBearer {
			if account := unverifiedSubject(form.Get("assertion")); account != "" {
				issued = append(issued, outcomeLimit{"jwt_bearer_tokens", "account:" + account, DefaultJWTBearerAccountLimit})
			}
		}
		for _, l := range append(failures, issued...) {
			res, exhausted, err := ratelimit.Exhausted(ctx, s.rates, l.name, l.key, l.limit)
			if err != nil {
				logger.Error("rate limit storage failed", "policy", l.name, "error", err)
				http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
				return
			}
			if exhausted {
				logger.Warn("token request refused: rate limit", "policy", l.name)
				ratelimit.WriteHeaders(w.Header(), l.name, l.limit, res)
				ratelimit.WriteTooManyRequests(w, res.RetryAfter)
				return
			}
		}
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		var count []outcomeLimit
		switch rec.status {
		case http.StatusUnauthorized:
			// Fosite answers invalid_client with 401.
			count = failures
		case http.StatusOK:
			count = issued
		}
		for _, l := range count {
			if _, err := ratelimit.Record(ctx, s.rates, l.name, l.key, l.limit); err != nil && !errors.Is(err, ratelimit.ErrTooManyKeys) {
				logger.Error("rate limit storage failed", "policy", l.name, "error", err)
			}
		}
	})
}

type outcomeLimit struct {
	name, key string
	limit     ratelimit.Limit
}

// unverifiedSubject returns the sub claim of a JWT without verifying it:
// it is only a counter key, and a forged assertion is never counted,
// because only issued tokens are.
func unverifiedSubject(assertion string) string {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 || len(parts[1]) > 8192 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || len(claims.Sub) > 256 {
		return ""
	}
	return claims.Sub
}

// statusRecorder records the status a handler writes.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush forwards to the underlying writer when it can flush.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack forwards to the underlying writer when it can hijack.
func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("systemauth: the response writer cannot hijack")
	}
	return h.Hijack()
}
