package bff

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/grokify/goauth/dpop"
)

// ProxyConfig contains configuration for the API proxy.
type ProxyConfig struct {
	// TargetURL is the base URL of the API backend.
	TargetURL string

	// UseDPoP enables DPoP proof injection.
	// Default: true
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

	// HeadersToForward specifies which request headers to forward.
	// If empty, forwards all headers except hop-by-hop headers.
	HeadersToForward []string

	// HeadersToRemove specifies headers to remove from the proxied request.
	HeadersToRemove []string

	// ResponseHeadersToRemove specifies headers to remove from the response.
	ResponseHeadersToRemove []string
}

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

		// Clone the request and add to context for director
		req := r.Clone(r.Context())
		req = req.WithContext(contextWithSession(req.Context(), session))

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

	// Apply path transformations
	path := req.URL.Path
	if p.config.StripPrefix != "" {
		path = strings.TrimPrefix(path, p.config.StripPrefix)
		if path == "" {
			path = "/"
		}
	}
	if p.config.PathRewrite != nil {
		path = p.config.PathRewrite(path)
	}
	req.URL.Path = singleJoiningSlash(p.targetURL.Path, path)

	// Set host header
	req.Host = p.targetURL.Host

	// Remove specified headers
	for _, h := range p.config.HeadersToRemove {
		req.Header.Del(h)
	}

	// Remove hop-by-hop headers
	removeHopByHopHeaders(req.Header)

	if session != nil {
		// Inject Authorization header
		authScheme := "Bearer"
		if p.config.UseDPoP && session.HasDPoP() {
			authScheme = "DPoP"
		}
		req.Header.Set("Authorization", authScheme+" "+session.AccessToken)

		// Inject DPoP proof if enabled
		if p.config.UseDPoP && session.HasDPoP() {
			proof, err := p.createDPoPProof(session, req.Method, req.URL)
			if err == nil {
				req.Header.Set("DPoP", proof)
			}
		}

		// Call custom rewrite hook
		if p.config.OnRequestRewrite != nil {
			p.config.OnRequestRewrite(req, session)
		}
	}
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
	targetPath := path
	if p.config.StripPrefix != "" {
		targetPath = strings.TrimPrefix(targetPath, p.config.StripPrefix)
	}
	if p.config.PathRewrite != nil {
		targetPath = p.config.PathRewrite(targetPath)
	}

	u := *p.targetURL
	u.Path = singleJoiningSlash(p.targetURL.Path, targetPath)

	// Create request
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, err
	}

	// Inject auth
	authScheme := "Bearer"
	if p.config.UseDPoP && session.HasDPoP() {
		authScheme = "DPoP"
	}
	req.Header.Set("Authorization", authScheme+" "+session.AccessToken)

	// Inject DPoP proof if enabled
	if p.config.UseDPoP && session.HasDPoP() {
		proof, err := p.createDPoPProof(session, method, &u)
		if err == nil {
			req.Header.Set("DPoP", proof)
		}
	}

	// Send request
	return p.client.Do(req) //nolint:gosec // G704: requests to token endpoint with configured URL
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
