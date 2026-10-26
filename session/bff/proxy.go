package bff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/grokify/goauth/dpop"
)

// ProxyConfig contains configuration for the API proxy.
type ProxyConfig struct {
	// TargetURL is the base URL of the API backend. Proxied paths always
	// stay under its path: requests with "." or ".." segments, encoded
	// slashes or backslashes, or a PathRewrite result outside the base are
	// rejected with 400 (ErrInvalidProxyPath).
	TargetURL string

	// UseDPoP enables DPoP proofs for sessions whose access token was
	// issued DPoP-bound (Session.TokenType "DPoP"): such a token is sent
	// with the DPoP scheme and a proof by the session's key. A token
	// issued as Bearer is always sent as Bearer. With UseDPoP off, a
	// DPoP-bound session cannot be proxied. Default: true.
	UseDPoP bool

	// Client is the HTTP client to use for proxied requests.
	// If nil, uses http.DefaultClient.
	Client *http.Client

	// Timeout is the request timeout.
	// Default: 30 seconds.
	Timeout time.Duration

	// OnError is called when a proxy error occurs.
	// If nil, returns 502 Bad Gateway.
	OnError func(w http.ResponseWriter, r *http.Request, err error)

	// OnRequestRewrite allows modifying the proxied request before sending.
	OnRequestRewrite func(r *http.Request, session *Session)

	// PathRewrite allows modifying the request path.
	// The function receives the original path and returns the rewritten path.
	PathRewrite func(path string) string

	// StripPrefix removes a prefix from the request path before proxying.
	StripPrefix string

	// HeadersToForward is an allow-list of request headers to forward.
	// When set, every other browser header is dropped before the session
	// credentials are injected; Content-Type, Content-Encoding and
	// Content-Length are always kept so request bodies stay intact. If
	// empty, all headers are forwarded except hop-by-hop headers.
	//
	// Either way the proxy strips the browser's credentials (Cookie,
	// Authorization, DPoP, X-API-Key) and client identity and routing
	// headers (X-App-ID, X-Real-IP, X-Remote-User, True-Client-IP,
	// CF-Connecting-IP, Forwarded, and any X-User-*, X-Principal-*,
	// X-Organization-*, X-Org-*, X-Tenant-*, X-Authenticated-* or
	// X-Forwarded-* header), even if listed here. Set such headers from
	// the session in OnRequestRewrite, which runs afterwards.
	HeadersToForward []string

	// HeadersToRemove specifies headers to remove from the proxied request.
	HeadersToRemove []string

	// ResponseHeadersToRemove specifies headers to remove from the response.
	ResponseHeadersToRemove []string
}

// ErrInvalidProxyPath is returned for a request path the proxy refuses to
// forward: one with "." or ".." segments, an encoded slash or backslash, or
// one that would resolve outside the upstream base path (the path of
// ProxyConfig.TargetURL). Proxied requests carry the user's credentials, so
// the upstream must only ever see paths under the configured base.
var ErrInvalidProxyPath = errors.New("invalid proxy path")

// upstreamPathKey carries the validated upstream path from Handler to
// rewriteRequest.
type upstreamPathKey struct{}

// alwaysStripHeaders are removed from every proxied request regardless of
// ProxyConfig.HeadersToRemove.
var alwaysStripHeaders = []string{"Cookie", "Authorization", "DPoP", "X-Api-Key"}

// clientIdentityHeaders are request headers that upstreams commonly trust to
// identify the user, tenant, app or client address. The proxy strips them,
// and any header starting with one of clientIdentityHeaderPrefixes, from
// every browser request, even when HeadersToForward lists them: the browser
// must not be able to assert an identity next to the session's credentials.
// OnRequestRewrite runs afterwards and can set them from the session.
var clientIdentityHeaders = []string{
	"X-App-Id",
	"X-Real-Ip",
	"X-Remote-User",
	"True-Client-Ip",
	"Cf-Connecting-Ip",
	"Forwarded",
}

// clientIdentityHeaderPrefixes are header-name prefixes stripped like
// clientIdentityHeaders. Header names are compared in canonical form.
var clientIdentityHeaderPrefixes = []string{
	"X-User-",
	"X-Principal-",
	"X-Organization-",
	"X-Org-",
	"X-Tenant-",
	"X-Authenticated-",
	"X-Forwarded-",
}

// alwaysForwardHeaders survive a HeadersToForward allow-list because the
// request body cannot be interpreted without them.
var alwaysForwardHeaders = []string{"Content-Type", "Content-Encoding", "Content-Length"}

// DefaultProxyConfig returns default proxy configuration.
func DefaultProxyConfig() ProxyConfig {
	return ProxyConfig{
		UseDPoP: true,
		Timeout: 30 * time.Second,
		HeadersToRemove: []string{
			"Cookie",
			"Authorization",
		},
		ResponseHeadersToRemove: []string{
			"Set-Cookie",
		},
	}
}

// Proxy proxies requests to an API backend with session-based authentication.
type Proxy struct {
	config       ProxyConfig
	targetURL    *url.URL
	client       *http.Client
	reverseProxy *httputil.ReverseProxy
}

// NewProxy creates a new API proxy.
func NewProxy(config ProxyConfig) (*Proxy, error) {
	target, err := url.Parse(config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	if target.Scheme == "" || target.Host == "" {
		return nil, fmt.Errorf("target URL must include scheme and host")
	}

	client := config.Client
	if client == nil {
		client = &http.Client{
			Timeout: config.Timeout,
		}
	}

	p := &Proxy{
		config:    config,
		targetURL: target,
		client:    client,
	}

	// Create reverse proxy for streaming responses
	p.reverseProxy = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// pr.Out is cloned from the inbound request with a derived context,
			// so the session value set in Handler propagates to it and
			// rewriteRequest can inject auth and DPoP headers.
			p.rewriteRequest(pr.Out)
		},
		ModifyResponse: func(resp *http.Response) error {
			p.modifyResponse(resp)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.handleError(w, r, err)
		},
		Transport: client.Transport,
	}

	return p, nil
}

// Handler returns an HTTP handler that proxies requests.
func (p *Proxy) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session from context
		session := GetSession(r.Context())
		if session == nil {
			p.handleError(w, r, ErrSessionNotFound)
			return
		}

		// Check if access token is expired
		if session.IsAccessTokenExpired() {
			p.handleError(w, r, ErrSessionExpired)
			return
		}

		// Resolve the upstream path before anything is forwarded, so a
		// path that would escape the upstream base never leaves the BFF.
		if hasEncodedSeparator(r.URL.EscapedPath()) {
			p.handleError(w, r, ErrInvalidProxyPath)
			return
		}
		upstreamPath, err := p.upstreamPath(r.URL.Path)
		if err != nil {
			p.handleError(w, r, err)
			return
		}

		// Clone the request and add to context for director
		req := r.Clone(r.Context())
		ctx := contextWithSession(req.Context(), session)
		ctx = context.WithValue(ctx, upstreamPathKey{}, upstreamPath)
		req = req.WithContext(ctx)

		// Use reverse proxy
		p.reverseProxy.ServeHTTP(w, req) //nolint:gosec // G704: proxy is designed to forward to configured backend URL
	})
}

// rewriteRequest rewrites the request for proxying.
func (p *Proxy) rewriteRequest(req *http.Request) {
	session := GetSession(req.Context())

	// Rewrite URL
	req.URL.Scheme = p.targetURL.Scheme
	req.URL.Host = p.targetURL.Host

	// Handler validated and resolved the path; reaching here without it
	// means the reverse proxy was invoked some other way.
	upstreamPath, ok := req.Context().Value(upstreamPathKey{}).(string)
	if !ok {
		panic("bff: proxy request reached rewrite without a validated path")
	}
	req.URL.Path = upstreamPath
	req.URL.RawPath = ""

	// Set host header
	req.Host = p.targetURL.Host

	// Never forward the browser's credentials, whatever the configuration
	// says: the session cookie would hand the upstream the user's BFF session,
	// and a client-supplied Authorization or DPoP header must not stand in for
	// the one injected below. OnRequestRewrite can add anything back.
	for _, h := range alwaysStripHeaders {
		req.Header.Del(h)
	}
	p.filterClientHeaders(req.Header)

	// Remove specified headers
	for _, h := range p.config.HeadersToRemove {
		req.Header.Del(h)
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)

	if session != nil {
		// Inject the credentials. A failure leaves the request without
		// them, so the API refuses it rather than seeing a token used
		// without its proof.
		if err := p.authorize(req, session); err != nil {
			slog.Default().ErrorContext(req.Context(), "bff: presenting the session's access token", "error", err)
		}

		// Call custom rewrite hook
		if p.config.OnRequestRewrite != nil {
			p.config.OnRequestRewrite(req, session)
		}
	}
}

// filterClientHeaders applies the HeadersToForward allow-list and strips
// client identity headers from a proxied request.
func (p *Proxy) filterClientHeaders(h http.Header) {
	if len(p.config.HeadersToForward) > 0 {
		allowed := make(map[string]bool, len(p.config.HeadersToForward)+len(alwaysForwardHeaders))
		for _, name := range p.config.HeadersToForward {
			allowed[http.CanonicalHeaderKey(name)] = true
		}
		for _, name := range alwaysForwardHeaders {
			allowed[name] = true
		}
		for name := range h {
			if !allowed[http.CanonicalHeaderKey(name)] {
				delete(h, name)
			}
		}
	}

	for _, name := range clientIdentityHeaders {
		h.Del(name)
	}
	for name := range h {
		canonical := http.CanonicalHeaderKey(name)
		for _, prefix := range clientIdentityHeaderPrefixes {
			if strings.HasPrefix(canonical, prefix) {
				delete(h, name)
				break
			}
		}
	}
}

// ErrDPoPUnavailable is returned when a session's access token was issued
// as DPoP-bound but the proxy cannot make a proof for it: DPoP is off
// (ProxyConfig.UseDPoP) or the session has no key pair.
var ErrDPoPUnavailable = errors.New("bff: the access token is DPoP-bound but no DPoP proof can be made")

// authorize sets the credentials of a proxied request by how the token
// endpoint issued the session's access token: a DPoP token (token_type
// DPoP) with the DPoP scheme and a proof by the session's key, a bearer
// token with the Bearer scheme and no proof. Sending a DPoP-bound token as
// Bearer, or a bearer token as DPoP, would be refused.
func (p *Proxy) authorize(req *http.Request, session *Session) error {
	if !session.UsesDPoP() {
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		return nil
	}
	if !p.config.UseDPoP || !session.HasDPoP() {
		return ErrDPoPUnavailable
	}
	proof, err := p.createDPoPProof(session, req.Method, req.URL)
	if err != nil {
		return fmt.Errorf("bff: creating a DPoP proof: %w", err)
	}
	req.Header.Set("Authorization", "DPoP "+session.AccessToken)
	req.Header.Set("DPoP", proof)
	return nil
}

// createDPoPProof creates a DPoP proof for the proxied request.
func (p *Proxy) createDPoPProof(session *Session, method string, u *url.URL) (string, error) {
	kp, err := session.GetDPoPKeyPair()
	if err != nil {
		return "", err
	}

	// Build the target URI for the proof
	uri := u.Scheme + "://" + u.Host + u.Path

	// Create proof with access token binding
	opts := dpop.ProofOptions{
		AccessToken: session.AccessToken,
	}

	return dpop.CreateProofWithOptions(kp, method, uri, opts)
}

// modifyResponse modifies the response before sending to client.
func (p *Proxy) modifyResponse(resp *http.Response) {
	// Remove specified response headers
	for _, h := range p.config.ResponseHeadersToRemove {
		resp.Header.Del(h)
	}
}

// handleError handles proxy errors.
func (p *Proxy) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if p.config.OnError != nil {
		p.config.OnError(w, r, err)
		return
	}

	if err == ErrSessionNotFound {
		http.Error(w, "Unauthorized: No session", http.StatusUnauthorized)
		return
	}

	if err == ErrSessionExpired {
		http.Error(w, "Unauthorized: Session expired", http.StatusUnauthorized)
		return
	}

	if err == ErrInvalidProxyPath {
		http.Error(w, "Bad Request: Invalid path", http.StatusBadRequest)
		return
	}

	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

// ProxyRequest proxies a single request (for non-streaming use cases).
func (p *Proxy) ProxyRequest(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	session := GetSession(ctx)
	if session == nil {
		return nil, ErrSessionNotFound
	}

	if session.IsAccessTokenExpired() {
		return nil, ErrSessionExpired
	}

	// Build target URL
	targetPath, err := p.upstreamPath(path)
	if err != nil {
		return nil, err
	}

	u := *p.targetURL
	u.Path = targetPath
	u.RawPath = ""

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}

	// Inject auth
	if err := p.authorize(req, session); err != nil {
		return nil, err
	}

	// Send request
	return p.client.Do(req) //nolint:gosec // G704: requests to token endpoint with configured URL
}

// upstreamPath maps a request path (decoded) onto the upstream: it applies
// StripPrefix and PathRewrite, joins the result onto the TargetURL path, and
// returns ErrInvalidProxyPath if the path has dot segments, a backslash or a
// NUL, or does not stay under the TargetURL path.
func (p *Proxy) upstreamPath(reqPath string) (string, error) {
	rel := reqPath
	if p.config.StripPrefix != "" {
		rel = strings.TrimPrefix(rel, p.config.StripPrefix)
		if rel == "" {
			rel = "/"
		}
	}
	if p.config.PathRewrite != nil {
		rel = p.config.PathRewrite(rel)
	}
	if hasUnsafeSegment(rel) {
		return "", ErrInvalidProxyPath
	}

	joined := singleJoiningSlash(p.targetURL.Path, rel)

	base := path.Clean("/" + p.targetURL.Path)
	cleaned := path.Clean("/" + joined)
	if base != "/" && cleaned != base && !strings.HasPrefix(cleaned, base+"/") {
		return "", ErrInvalidProxyPath
	}
	return joined, nil
}

// hasUnsafeSegment reports whether p contains a "." or ".." segment, a
// backslash (which some servers treat as a separator) or a NUL byte.
func hasUnsafeSegment(p string) bool {
	if strings.ContainsAny(p, "\\\x00") {
		return true
	}
	for seg := range strings.SplitSeq(p, "/") {
		if seg == "." || seg == ".." {
			return true
		}
	}
	return false
}

// hasEncodedSeparator reports whether an escaped path contains an encoded
// slash or backslash, which the upstream might decode into a separator the
// BFF never saw.
func hasEncodedSeparator(escaped string) bool {
	lower := strings.ToLower(escaped)
	return strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c")
}

// contextWithSession adds the session to the context.
func contextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, ContextKeySession, session)
}

// singleJoiningSlash joins two paths with a single slash.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

// removeHopByHopHeaders removes hop-by-hop headers from the request.
func removeHopByHopHeaders(h http.Header) {
	// Remove headers listed in Connection header first (before deleting Connection itself)
	if c := h.Get("Connection"); c != "" {
		for f := range strings.SplitSeq(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}

	// RFC 2616, section 13.5.1
	hopByHopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
	}
	for _, header := range hopByHopHeaders {
		h.Del(header)
	}
}

// APIProxyMiddleware creates middleware that proxies all requests to an API backend.
// This is useful for wrapping the proxy handler with session middleware.
func APIProxyMiddleware(targetURL string) (func(http.Handler) http.Handler, error) {
	config := DefaultProxyConfig()
	config.TargetURL = targetURL

	proxy, err := NewProxy(config)
	if err != nil {
		return nil, err
	}

	return func(next http.Handler) http.Handler {
		return proxy.Handler()
	}, nil
}

// SimpleProxy creates a simple proxy handler with default configuration.
func SimpleProxy(targetURL string) (http.Handler, error) {
	config := DefaultProxyConfig()
	config.TargetURL = targetURL

	proxy, err := NewProxy(config)
	if err != nil {
		return nil, err
	}

	return proxy.Handler(), nil
}
