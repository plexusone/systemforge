package bff

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIPConfig contains configuration for client IP extraction.
type ClientIPConfig struct {
	// TrustCloudflare enables Cloudflare header support.
	// When true, checks CF-Connecting-IP and True-Client-IP headers.
	// Default: false.
	TrustCloudflare bool

	// TrustProxy enables standard proxy headers (X-Forwarded-For, X-Real-IP)
	// from the requests TrustedProxies admits. It has no effect without
	// TrustedProxies: headers are never believed from an unknown peer.
	// Default: false.
	TrustProxy bool

	// TrustedProxies is the list of proxy IP ranges whose forwarding
	// headers are believed, in CIDR notation (e.g., "10.0.0.0/8") or as
	// single addresses.
	TrustedProxies []string

	// CloudflareIPRanges are the ranges Cloudflare connects from, which
	// CF-Connecting-IP and True-Client-IP are believed from. Required for
	// TrustCloudflare to have any effect: any client can send those
	// headers, so they are ignored without ranges proving the request came
	// through Cloudflare. Cloudflare publishes the ranges at
	// https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6
	CloudflareIPRanges []string

	trustedNets    []*net.IPNet
	cloudflareNets []*net.IPNet
}

// isZero reports whether no client IP handling was configured.
func (c ClientIPConfig) isZero() bool {
	return !c.TrustCloudflare && !c.TrustProxy && len(c.TrustedProxies) == 0 && len(c.CloudflareIPRanges) == 0
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
func CloudflareClientIPConfig() ClientIPConfig {
	return ClientIPConfig{
		TrustCloudflare: true,
		TrustProxy:      true, // Cloudflare also sets X-Forwarded-For
	}
}

// ClientIPExtractor extracts the real client IP from requests.
type ClientIPExtractor struct {
	config ClientIPConfig
}

// NewClientIPExtractor creates a new client IP extractor.
func NewClientIPExtractor(config ClientIPConfig) *ClientIPExtractor {
	e := &ClientIPExtractor{config: config}

	// Parse trusted proxy ranges
	for _, cidr := range config.TrustedProxies {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			e.config.trustedNets = append(e.config.trustedNets, ipNet)
		} else if ip := net.ParseIP(cidr); ip != nil {
			// Single IP, convert to /32 or /128
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			e.config.trustedNets = append(e.config.trustedNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}

	// Parse Cloudflare IP ranges
	for _, cidr := range config.CloudflareIPRanges {
		if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
			e.config.cloudflareNets = append(e.config.cloudflareNets, ipNet)
		}
	}

	return e
}

// GetClientIP extracts the real client IP from the request.
// It checks headers in order of trust: Cloudflare > Proxy > RemoteAddr. A
// header is believed only when the direct peer is in the configured
// Cloudflare or proxy ranges and the value is a valid IP address;
// otherwise the result is the direct peer's address.
func (e *ClientIPExtractor) GetClientIP(r *http.Request) string {
	remoteIP := extractIP(r.RemoteAddr)

	// Check Cloudflare headers if enabled
	if e.IsCloudflareRequest(r) {
		// CF-Connecting-IP is the most reliable
		if ip, ok := validIP(r.Header.Get("CF-Connecting-IP")); ok {
			return ip
		}
		// True-Client-IP is available on Enterprise plans
		if ip, ok := validIP(r.Header.Get("True-Client-IP")); ok {
			return ip
		}
	}

	// Check standard proxy headers if enabled
	if e.config.TrustProxy && e.isTrustedProxy(remoteIP) {
		// X-Real-IP is typically set by nginx
		if ip, ok := validIP(r.Header.Get("X-Real-IP")); ok {
			return ip
		}
		// X-Forwarded-For contains a chain; the first untrusted IP is the client
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip, ok := e.parseXForwardedFor(xff); ok {
				return ip
			}
		}
	}

	if ip, ok := validIP(remoteIP); ok {
		return ip
	}
	return remoteIP
}

// IsCloudflareRequest reports whether Cloudflare handling is enabled and
// the request's direct peer is in the configured Cloudflare ranges, so
// its Cloudflare headers can be believed.
func (e *ClientIPExtractor) IsCloudflareRequest(r *http.Request) bool {
	return e.config.TrustCloudflare && e.isCloudflareRequest(extractIP(r.RemoteAddr))
}

// validIP returns the canonical form of s when it is an IP address.
func validIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", false
	}
	return addr.Unmap().String(), true
}

// isCloudflareRequest checks if the request comes from Cloudflare. Without
// configured ranges nothing is known to be Cloudflare.
func (e *ClientIPExtractor) isCloudflareRequest(remoteIP string) bool {
	if len(e.config.cloudflareNets) == 0 {
		return false
	}

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}

	for _, ipNet := range e.config.cloudflareNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isTrustedProxy checks if the remote IP is a trusted proxy. Without
// configured proxies none is.
func (e *ClientIPExtractor) isTrustedProxy(remoteIP string) bool {
	if len(e.config.trustedNets) == 0 {
		return false
	}

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}

	for _, ipNet := range e.config.trustedNets {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// parseXForwardedFor extracts the client IP from an X-Forwarded-For
// header: the first address from the right that is not a trusted proxy.
// Each proxy appends the peer it saw, so the right-hand entries are
// written by proxies we trust and the left-hand ones by the client. It
// reports false when the chain holds nothing usable.
func (e *ClientIPExtractor) parseXForwardedFor(xff string) (string, bool) {
	// X-Forwarded-For: client, proxy1, proxy2
	ips := strings.Split(xff, ",")
	for i := len(ips) - 1; i >= 0; i-- {
		ip, ok := validIP(ips[i])
		if !ok {
			return "", false
		}
		if !e.isTrustedProxy(ip) {
			return ip, true
		}
	}
	return "", false
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
