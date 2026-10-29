package ratelimit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/observability"
	"github.com/plexusone/systemforge/session/clientaddr"
	"github.com/plexusone/systemforge/session/middleware"
)

// Key kinds of a route limit.
const (
	// KeyAddress limits each client address (see clientaddr).
	KeyAddress KeyKind = "address"
	// KeyClient limits each OAuth client, named by HTTP Basic credentials
	// or the client_id form field.
	KeyClient KeyKind = "client"
)

// KeyKind says what a route limit counts requests by.
type KeyKind string

// Default limits of the layers.
var (
	// DefaultAddressLimit is the default layer's limit per client address:
	// generous, so that only floods reach it.
	DefaultAddressLimit = PerMinute(300)

	// DefaultSignedInLimit is the limit per signed-in principal or service
	// account, checked after authentication.
	DefaultSignedInLimit = PerMinute(1200)
)

// Names of the default route policies, for overriding them by name with
// MergeRoutes.
const (
	RouteToken          = "token"
	RouteLogin          = "login"
	RouteSignup         = "signup"
	RouteBFFAuth        = "bff_auth"
	RouteHealth         = "health"
	RouteStatic         = "static"
	RoutePaymentWebhook = "payment_webhook"
)

// RouteLimit is one limit of a route policy and what it counts by.
type RouteLimit struct {
	Key   KeyKind
	Limit Limit
}

// Route is a route policy: the paths it covers, and either an exemption
// from address limits or limits checked after the default layer.
type Route struct {
	// Name names the policy in keys and in the RateLimit-Policy header.
	Name string

	// Paths are matched against the request path: "/oauth/token" matches
	// that path only, "/login*" every path starting with "/login", and
	// "/bff/auth/*" every path under "/bff/auth/" (and "/bff/auth"). When
	// several routes match, the longest pattern wins.
	Paths []string

	// Methods restricts the route to these methods; empty matches all.
	Methods []string

	// Exempt skips the default layer and every route limit, for health
	// checks, static assets, and callers whose addresses are shared, such
	// as a payment provider's webhooks.
	Exempt bool

	// Limits are checked in order after the default layer.
	Limits []RouteLimit

	// FailOpen lets requests through when the storage fails. Routes fail
	// closed by default: the credential endpoints refuse rather than run
	// without limits.
	FailOpen bool
}

// DefaultRoutes is the default route table: the token endpoint limited per
// address and per client; login, sign-up and the BFF's authentication
// endpoints limited per address, lower than the default; health checks,
// static assets and the payment webhook exempt. Change entries by name
// with MergeRoutes.
func DefaultRoutes() []Route {
	return []Route{
		{Name: RouteToken, Paths: []string{"/oauth/token"}, Limits: []RouteLimit{
			{Key: KeyAddress, Limit: PerMinute(120)},
			{Key: KeyClient, Limit: PerMinute(1200)},
		}},
		{Name: RouteLogin, Paths: []string{"/login*"}, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(120)}}},
		{Name: RouteSignup, Paths: []string{"/signup*"}, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(60)}}},
		{Name: RouteBFFAuth, Paths: []string{"/bff/auth/*"}, Limits: []RouteLimit{{Key: KeyAddress, Limit: PerMinute(120)}}},
		{Name: RouteHealth, Paths: []string{"/healthz", "/readyz", "/livez", "/health"}, Exempt: true},
		{Name: RouteStatic, Paths: []string{"/static/*", "/assets/*", "/favicon.ico", "/robots.txt"}, Exempt: true},
		{Name: RoutePaymentWebhook, Paths: []string{"/billing/webhook"}, Exempt: true},
	}
}

// MergeRoutes returns base with each override replacing the route of the
// same name, and overrides with new names appended. base is not modified.
func MergeRoutes(base []Route, overrides ...Route) []Route {
	out := slices.Clone(base)
	for _, o := range overrides {
		i := slices.IndexFunc(out, func(r Route) bool { return r.Name == o.Name })
		if i >= 0 {
			out[i] = o
		} else {
			out = append(out, o)
		}
	}
	return out
}

// PolicyConfig configures a Policy.
type PolicyConfig struct {
	// Storage keeps the counters (required): MemoryStorage for one
	// instance, RedisStorage when several share the limits.
	Storage Storage

	// Address finds the client address (see clientaddr). Nil uses the
	// direct peer.
	Address *clientaddr.Resolver

	// Default is the default layer's limit per address. Zero uses
	// DefaultAddressLimit; DisableDefault turns the layer off.
	Default        Limit
	DisableDefault bool

	// DefaultFailClosed answers 503 when the storage fails on the default
	// layer. By default the default layer lets requests through and logs;
	// the route limits of the credential endpoints still refuse.
	DefaultFailClosed bool

	// Routes is the route table. Nil uses DefaultRoutes; an empty non-nil
	// table has no route policies.
	Routes []Route

	// ExemptNetworks are client networks, in CIDR notation or as single
	// addresses, exempt from every limit: back-channel callers such as
	// relying parties' servers.
	ExemptNetworks []string

	// KnownClient reports whether an OAuth client exists. With it, client
	// limits give only registered clients their own bucket, and requests
	// naming others share one, so made-up client IDs cannot grow the
	// storage. Optional.
	KnownClient func(ctx context.Context, clientID string) bool

	// Logger receives storage failures. Default: slog.Default().
	Logger *slog.Logger

	// Observability records metrics. Optional.
	Observability *observability.Observability
}

// Policy is the rate limiting a server applies before authentication: a
// default limit per client address on every route, and route policies for
// the credential endpoints. Install its Middleware outermost, before
// authentication; put a signed-in limit (NewSignedInLimiter) after it.
type Policy struct {
	storage        Storage
	address        *clientaddr.Resolver
	def            Limit
	defaultOn      bool
	defaultOpen    bool
	routes         []Route
	exempt         []netip.Prefix
	knownClient    func(ctx context.Context, clientID string) bool
	logger         *slog.Logger
	observability  *observability.Observability
	unknownClients string
}

// NewPolicy builds a Policy.
func NewPolicy(cfg PolicyConfig) (*Policy, error) {
	if cfg.Storage == nil {
		return nil, errors.New("ratelimit: policy storage is required")
	}
	exempt, err := clientaddr.ParseNetworks(cfg.ExemptNetworks)
	if err != nil {
		return nil, fmt.Errorf("ratelimit: exempt networks: %w", err)
	}
	routes := cfg.Routes
	if routes == nil {
		routes = DefaultRoutes()
	}
	seen := map[string]bool{}
	for _, rt := range routes {
		if err := rt.validate(); err != nil {
			return nil, err
		}
		if seen[rt.Name] {
			return nil, fmt.Errorf("ratelimit: route %q is listed twice", rt.Name)
		}
		seen[rt.Name] = true
	}
	def := cfg.Default
	if def.Rate <= 0 {
		def = DefaultAddressLimit
	}
	if def.Period <= 0 {
		return nil, errors.New("ratelimit: the default limit needs a period")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Policy{
		storage:        cfg.Storage,
		address:        cfg.Address,
		def:            def,
		defaultOn:      !cfg.DisableDefault,
		defaultOpen:    !cfg.DefaultFailClosed,
		routes:         slices.Clone(routes),
		exempt:         exempt,
		knownClient:    cfg.KnownClient,
		logger:         logger,
		observability:  cfg.Observability,
		unknownClients: "unknown",
	}, nil
}

func (rt Route) validate() error {
	if rt.Name == "" {
		return errors.New("ratelimit: a route needs a name")
	}
	if len(rt.Paths) == 0 {
		return fmt.Errorf("ratelimit: route %q has no paths", rt.Name)
	}
	for _, p := range rt.Paths {
		if !strings.HasPrefix(p, "/") || strings.Contains(strings.TrimSuffix(p, "*"), "*") {
			return fmt.Errorf("ratelimit: route %q: path %q must start with / and may end with *", rt.Name, p)
		}
	}
	if rt.Exempt && len(rt.Limits) > 0 {
		return fmt.Errorf("ratelimit: route %q is exempt but has limits", rt.Name)
	}
	for _, l := range rt.Limits {
		if l.Key != KeyAddress && l.Key != KeyClient {
			return fmt.Errorf("ratelimit: route %q: unknown key %q (want address or client)", rt.Name, l.Key)
		}
		if l.Limit.Rate <= 0 || l.Limit.Period <= 0 {
			return fmt.Errorf("ratelimit: route %q: a limit needs a positive rate and period", rt.Name)
		}
	}
	return nil
}

// Routes returns the route table in effect.
func (p *Policy) Routes() []Route { return slices.Clone(p.routes) }

// Storage returns the policy's storage, for handler limits that share it.
func (p *Policy) Storage() Storage { return p.storage }

// Address returns the client-address resolver.
func (p *Policy) Address() *clientaddr.Resolver { return p.address }

// Route returns the route policy for a request, if one matches. Paths are
// matched relative to where the policy is mounted: inside a chi router
// mounted with Mount, the path below the mount point.
func (p *Policy) Route(r *http.Request) (Route, bool) {
	reqPath := r.URL.Path
	if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
		reqPath = rctx.RoutePath
	}
	clean := path.Clean("/" + reqPath)
	best, bestScore := -1, -1
	for i, rt := range p.routes {
		if len(rt.Methods) > 0 && !slices.Contains(rt.Methods, r.Method) {
			continue
		}
		for _, pat := range rt.Paths {
			if score, ok := matchPath(pat, clean); ok && score > bestScore {
				best, bestScore = i, score
			}
		}
	}
	if best < 0 {
		return Route{}, false
	}
	return p.routes[best], true
}

// matchPath matches a route pattern against a cleaned path. The score
// prefers longer patterns and, at equal length, exact ones.
func matchPath(pattern, p string) (int, bool) {
	prefix, isPrefix := strings.CutSuffix(pattern, "*")
	if !isPrefix {
		return 2*len(pattern) + 1, p == pattern
	}
	if strings.HasPrefix(p, prefix) {
		return 2 * len(prefix), true
	}
	// "/bff/auth/*" also covers "/bff/auth".
	if dir, ok := strings.CutSuffix(prefix, "/"); ok && dir != "" && p == dir {
		return 2 * len(prefix), true
	}
	return 0, false
}

// policyAppliedKey marks a request a Policy has already limited.
type policyAppliedKey struct{}

// PolicyApplied reports whether a Policy has limited the request.
func PolicyApplied(ctx context.Context) bool { return ctx.Value(policyAppliedKey{}) != nil }

// check is one limit to check for a request.
type check struct {
	name     string
	key      string
	limit    Limit
	failOpen bool
}

// Middleware enforces the default layer and the route policies.
func (p *Policy) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A policy inside another (an embedded server's under the
			// application's) would count every request twice.
			if PolicyApplied(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), policyAppliedKey{}, true))
			addr, ok := p.address.Addr(r)
			address := "unknown"
			if ok {
				address = addr.String()
				if p.exemptAddr(addr) {
					next.ServeHTTP(w, r)
					return
				}
			}
			rt, matched := p.Route(r)
			if matched && rt.Exempt {
				next.ServeHTTP(w, r)
				return
			}
			var checks []check
			if p.defaultOn {
				checks = append(checks, check{name: DefaultPolicyName, key: "default:ip:" + address, limit: p.def, failOpen: p.defaultOpen})
			}
			if matched {
				for _, l := range rt.Limits {
					c := check{name: rt.Name, limit: l.Limit, failOpen: rt.FailOpen}
					switch l.Key {
					case KeyClient:
						c.name += "_client"
						c.key = rt.Name + ":client:" + p.clientBucket(r)
					default:
						c.key = rt.Name + ":ip:" + address
					}
					checks = append(checks, c)
				}
			}
			for _, c := range checks {
				if !p.enforce(w, r, c) {
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// enforce checks one limit, writing its headers, and answers the request
// and returns false when it must not go on.
func (p *Policy) enforce(w http.ResponseWriter, r *http.Request, c check) bool {
	ctx := r.Context()
	res, err := p.storage.Allow(ctx, c.key, c.limit)
	if errors.Is(err, ErrTooManyKeys) {
		p.logger.WarnContext(ctx, "rate limit storage is full", "policy", c.name)
		WriteTooManyRequests(w, tooManyKeysWait)
		return false
	}
	if err != nil {
		p.logger.ErrorContext(ctx, "rate limit storage failed", "policy", c.name, "error", err, "fail_open", c.failOpen)
		if c.failOpen {
			return true
		}
		writeUnavailable(w)
		return false
	}
	if p.observability != nil {
		p.observability.RecordRateLimitRequest(ctx, c.name, c.key, res.Allowed)
	}
	WriteHeaders(w.Header(), c.name, c.limit, res)
	if !res.Allowed {
		WriteTooManyRequests(w, res.RetryAfter)
		return false
	}
	return true
}

func (p *Policy) exemptAddr(a netip.Addr) bool {
	for _, n := range p.exempt {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// clientBucket is the client bucket of a request: the client ID it names,
// or "unknown" for none, an implausible one, or one KnownClient rejects.
func (p *Policy) clientBucket(r *http.Request) string {
	id := RequestClientID(r)
	if id == "" || len(id) > 256 {
		return p.unknownClients
	}
	if p.knownClient != nil && !p.knownClient(r.Context(), id) {
		return p.unknownClients
	}
	return id
}

// maxPeekBody bounds how much of a form body RequestClientID reads.
const maxPeekBody = 64 << 10

// RequestClientID returns the OAuth client a token request names: the
// HTTP Basic user name (form-decoded, RFC 6749 §2.3.1) or the client_id
// field of a form body. A body it reads is put back unchanged for the
// handler. It returns "" when the request names no client.
func RequestClientID(r *http.Request) string {
	if user, _, ok := r.BasicAuth(); ok {
		if id, err := url.QueryUnescape(user); err == nil {
			return id
		}
		return user
	}
	return PeekForm(r).Get("client_id")
}

// PeekForm returns the fields of a POST request's form body
// (application/x-www-form-urlencoded) without consuming it: the body is put
// back unchanged for the handler. Bodies over 64 KiB, other content types
// and unparseable bodies give no fields. When the form is already parsed it
// returns r.PostForm.
func PeekForm(r *http.Request) url.Values {
	if r.PostForm != nil {
		return r.PostForm
	}
	if r.Method != http.MethodPost || r.Body == nil || r.Body == http.NoBody {
		return url.Values{}
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/x-www-form-urlencoded" {
		return url.Values{}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxPeekBody+1))
	rest := r.Body
	if err != nil {
		// What was read goes back in front of the error, so the handler
		// sees the same bytes and the same failure.
		r.Body = readCloser{io.MultiReader(bytes.NewReader(body), errReader{err}), rest}
		return url.Values{}
	}
	r.Body = readCloser{io.MultiReader(bytes.NewReader(body), rest), rest}
	if len(body) > maxPeekBody {
		return url.Values{}
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return url.Values{}
	}
	return values
}

type readCloser struct {
	io.Reader
	io.Closer
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// SignedInKey keys on the signed-in caller: the principal (person or
// service account) requestprincipal or the JWT middleware put in the
// context. Requests without one get "", so pair it with WithSkip(Anonymous).
func SignedInKey() KeyFunc {
	return func(r *http.Request) string {
		return signedInID(r)
	}
}

// Anonymous reports whether a request has no signed-in caller in its
// context, for WithSkip.
func Anonymous(r *http.Request) bool { return signedInID(r) == "" }

// NewSignedInLimiter returns the limiter for signed-in callers, to install
// after authentication: keyed by principal or service account (SignedInKey),
// skipping anonymous requests, failing open, and named "signed_in". A zero
// limit uses DefaultSignedInLimit. opts are applied after these.
func NewSignedInLimiter(storage Storage, limit Limit, opts ...Option) *Limiter {
	if limit.Rate <= 0 {
		limit = DefaultSignedInLimit
	}
	base := []Option{
		WithLimit(limit),
		WithKeyFunc(SignedInKey()),
		WithSkip(Anonymous),
		WithFailOpen(),
		WithName("signed_in"),
	}
	return New(storage, append(base, opts...)...)
}

// Decision is the outcome of Check.
type Decision int

// Outcomes of Check.
const (
	// Allowed: the request is within the limit.
	Allowed Decision = iota
	// Refused: the limit is used up; the response was written.
	Refused
	// Unavailable: the storage failed and the check fails closed; the
	// response was written.
	Unavailable
)

// Check checks one limit inside a handler, on the storage the layers
// share, for limits that need the request's outcome or a key only the
// handler knows (an account, a service account). It writes the rate limit
// headers, and on refusal the 429 or 503 response; with failOpen a
// storage failure is logged and allowed. name names the policy in the
// headers and is the key's namespace.
func Check(w http.ResponseWriter, r *http.Request, storage Storage, name, key string, limit Limit, failOpen bool, logger *slog.Logger) Decision {
	if logger == nil {
		logger = slog.Default()
	}
	ctx := r.Context()
	res, err := storage.Allow(ctx, name+":"+key, limit)
	if errors.Is(err, ErrTooManyKeys) {
		logger.WarnContext(ctx, "rate limit storage is full", "policy", name)
		WriteTooManyRequests(w, tooManyKeysWait)
		return Refused
	}
	if err != nil {
		logger.ErrorContext(ctx, "rate limit storage failed", "policy", name, "error", err, "fail_open", failOpen)
		if failOpen {
			return Allowed
		}
		writeUnavailable(w)
		return Unavailable
	}
	WriteHeaders(w.Header(), name, limit, res)
	if !res.Allowed {
		WriteTooManyRequests(w, res.RetryAfter)
		return Refused
	}
	return Allowed
}

// Exhausted reports whether the limit for key is used up, without
// counting a request when the storage can look without counting (Peeker).
// Storage that cannot look reports false. It is for limits that count only
// some outcomes, such as failed authentication: check Exhausted before
// the work, and Record after a counted outcome.
func Exhausted(ctx context.Context, storage Storage, name, key string, limit Limit) (Result, bool, error) {
	pk, ok := storage.(Peeker)
	if !ok {
		return Result{Allowed: true}, false, nil
	}
	res, err := pk.Peek(ctx, name+":"+key, limit)
	if err != nil {
		return Result{}, false, err
	}
	return res, !res.Allowed, nil
}

// Record counts one outcome against the limit for key, as Check does,
// without answering the request.
func Record(ctx context.Context, storage Storage, name, key string, limit Limit) (Result, error) {
	return storage.Allow(ctx, name+":"+key, limit)
}

// Peeker is storage that can report a key's state without counting a
// request. MemoryStorage and RedisStorage implement it.
type Peeker interface {
	// Peek returns what Allow would return, without counting.
	Peek(ctx context.Context, key string, limit Limit) (Result, error)
}

// signedInID is the signed-in caller's key, or "".
func signedInID(r *http.Request) string {
	if p, ok := requestprincipal.FromContext(r.Context()); ok && p != nil && p.PrincipalID != "" {
		return "principal:" + p.PrincipalID
	}
	if id := middleware.PrincipalIDFromContext(r.Context()); id != uuid.Nil {
		return "principal:" + id.String()
	}
	return ""
}
