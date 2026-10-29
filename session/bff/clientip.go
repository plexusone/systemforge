package bff

import (
	"net"
	"net/http"
	"strings"

	"github.com/plexusone/systemforge/session/clientaddr"
)

// ClientIPConfig contains configuration for client IP extraction.
type ClientIPConfig struct {
	// Resolver finds the client address with the rule SystemAuth, appauth
	// and rate limiting share (see clientaddr): the trusted proxy
	// networks and the one header they write. When set, the fields below
	// are ignored.
	Resolver *clientaddr.Resolver

	// TrustCloudflare enables Cloudflare header support.
	// When true, checks CF-Connecting-IP and True-Client-IP headers.
	// Default: false.
	//
	// Deprecated: set Resolver with Header CF-Connecting-IP and the edge's
	// networks as TrustedProxies.
	TrustCloudflare bool

	// TrustProxy enables standard proxy headers (X-Forwarded-For, X-Real-IP)
	// from the requests TrustedProxies admits. It has no effect without
	// TrustedProxies: headers are never believed from an unknown peer.
	// Default: false.
	//
	// Deprecated: set Resolver.
	TrustProxy bool

	// TrustedProxies is the list of proxy IP ranges whose forwarding
	// headers are believed, in CIDR notation (e.g., "10.0.0.0/8") or as
	// single addresses. Invalid entries are ignored.
	//
	// Deprecated: set Resolver.
	TrustedProxies []string

	// CloudflareIPRanges are the ranges Cloudflare connects from, which
	// CF-Connecting-IP and True-Client-IP are believed from. Required for
	// TrustCloudflare to have any effect: any client can send those
	// headers, so they are ignored without ranges proving the request came
	// through Cloudflare. Cloudflare publishes the ranges at
	// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
	//
	// Deprecated: set Resolver.
	CloudflareIPRanges []string
}

// isZero reports whether no client IP handling was configured.
func (c ClientIPConfig) isZero() bool {
	return c.Resolver == nil && !c.TrustCloudflare && !c.TrustProxy && len(c.TrustedProxies) == 0 && len(c.CloudflareIPRanges) == 0
}

// DefaultClientIPConfig returns a safe default configuration.
// By default, no proxy headers are trusted.
func DefaultClientIPConfig() ClientIPConfig {
	return ClientIPConfig{
		TrustCloudflare: false,
		TrustProxy:      false,
	}
}

// CloudflareClientIPConfig returns configuration for Cloudflare
// deployments. The caller must set CloudflareIPRanges (and TrustedProxies
// for X-Forwarded-For); until then no forwarding header is believed.
//
// Deprecated: set ClientIPConfig.Resolver to a clientaddr.Resolver with
// Header CF-Connecting-IP and the edge's networks as TrustedProxies.
func CloudflareClientIPConfig() ClientIPConfig {
	return ClientIPConfig{
		TrustCloudflare: true,
		TrustProxy:      true, // Cloudflare also sets X-Forwarded-For
	}
}

// ClientIPExtractor extracts the real client IP from requests.
type ClientIPExtractor struct {
	// resolver, when set, is the whole rule.
	resolver *clientaddr.Resolver
	// sources are the legacy configuration's resolvers, tried in order:
	// CF-Connecting-IP, True-Client-IP, X-Real-IP, X-Forwarded-For.
	sources []*clientaddr.Resolver
	// cloudflare admits the requests whose Cloudflare headers are believed.
	cloudflare *clientaddr.Resolver
}

// NewClientIPExtractor creates a new client IP extractor.
func NewClientIPExtractor(config ClientIPConfig) *ClientIPExtractor {
	if config.Resolver != nil {
		e := &ClientIPExtractor{resolver: config.Resolver}
		if config.Resolver.Header() == http.CanonicalHeaderKey(clientaddr.HeaderCFConnectingIP) {
			e.cloudflare = config.Resolver
		}
		return e
	}
	e := &ClientIPExtractor{}
	if config.TrustCloudflare {
		if cf := validNetworks(config.CloudflareIPRanges); len(cf) > 0 {
			e.cloudflare = mustResolver(cf, clientaddr.HeaderCFConnectingIP)
			e.sources = append(e.sources, e.cloudflare, mustResolver(cf, clientaddr.HeaderTrueClientIP))
		}
	}
	if config.TrustProxy {
		if proxies := validNetworks(config.TrustedProxies); len(proxies) > 0 {
			e.sources = append(e.sources, mustResolver(proxies, clientaddr.HeaderXRealIP), mustResolver(proxies, clientaddr.HeaderXForwardedFor))
		}
	}
	return e
}

// validNetworks keeps the entries clientaddr accepts, as the legacy
// configuration ignored invalid ones.
func validNetworks(networks []string) []string {
	var out []string
	for _, n := range networks {
		if _, err := clientaddr.ParseNetworks([]string{n}); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// mustResolver builds a resolver from networks validNetworks accepted, so
// it cannot fail.
func mustResolver(networks []string, header string) *clientaddr.Resolver {
	return clientaddr.MustNew(clientaddr.Config{TrustedProxies: networks, Header: header})
}

// GetClientIP extracts the real client IP from the request. With a
// Resolver it is the Resolver's answer. With the legacy configuration it
// checks headers in order of trust (Cloudflare, then the proxy's, then
// RemoteAddr). A header is believed only when the direct peer is in the
// configured Cloudflare or proxy ranges and the value is a valid IP
// address; otherwise the result is the direct peer's address.
func (e *ClientIPExtractor) GetClientIP(r *http.Request) string {
	if e.resolver != nil {
		if ip := e.resolver.ClientIP(r); ip != "" {
			return ip
		}
		return extractIP(r.RemoteAddr)
	}
	for _, src := range e.sources {
		if a, ok := src.FromHeader(r); ok {
			return a.String()
		}
	}
	if ip := clientaddr.PeerIP(r); ip != "" {
		return ip
	}
	return extractIP(r.RemoteAddr)
}

// IsCloudflareRequest reports whether Cloudflare handling is enabled and
// the request's direct peer is in the configured Cloudflare ranges, so
// its Cloudflare headers can be believed. With a Resolver, it is enabled
// when the Resolver reads CF-Connecting-IP.
func (e *ClientIPExtractor) IsCloudflareRequest(r *http.Request) bool {
	return e.cloudflare != nil && e.cloudflare.TrustsPeer(r)
}

// extractIP extracts the IP address from a host:port string.
func extractIP(addr string) string {
	// Handle IPv6 addresses like [::1]:8080
	if strings.HasPrefix(addr, "[") {
		if idx := strings.Index(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		return strings.Trim(addr, "[]")
	}

	// Handle IPv4 addresses like 127.0.0.1:8080
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}

	return addr
}

// GetCloudflareMetadata extracts Cloudflare-specific metadata from the request.
func GetCloudflareMetadata(r *http.Request) map[string]string {
	metadata := make(map[string]string)

	// Ray ID for request tracing
	if ray := r.Header.Get("CF-Ray"); ray != "" {
		metadata["cf_ray"] = ray
	}

	// Country code
	if country := r.Header.Get("CF-IPCountry"); country != "" {
		metadata["cf_country"] = country
	}

	// Visitor scheme (http/https)
	if scheme := r.Header.Get("CF-Visitor"); scheme != "" {
		metadata["cf_visitor"] = scheme
	}

	// Bot detection (Enterprise)
	if botScore := r.Header.Get("CF-Bot-Score"); botScore != "" {
		metadata["cf_bot_score"] = botScore
	}

	return metadata
}
