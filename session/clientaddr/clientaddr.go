// Package clientaddr finds the address of the client behind a request: the
// one rule SystemAuth, the BFF, appauth and rate limiting share.
//
// A request's direct peer (http.Request.RemoteAddr) is the only address a
// client cannot choose. Behind reverse proxies the peer is the proxy, and
// the client's address is in a header the proxy writes. A Resolver believes
// that header only when the direct peer is one of the trusted proxy
// networks; from any other peer the header is ignored, because a client can
// send it too.
//
// Two kinds of header are supported:
//
//   - X-Forwarded-For (the default): a list each proxy appends the peer it
//     saw to. The Resolver reads it from the right, skipping trusted proxy
//     addresses, and takes the first address no trusted proxy vouched
//     for. A client can write anything at the left of the list, but not
//     past the proxy that appends to it.
//   - A single-value header, such as CF-Connecting-IP, True-Client-IP or
//     X-Real-IP, which the trusted proxy sets to one address.
//
// A typical deployment has a CDN or edge proxy, then a reverse proxy on the
// host that sets X-Forwarded-For to the address it took from the edge, then
// the application on loopback. There the trusted networks are loopback
// (see LoopbackProxy) and the header is X-Forwarded-For.
package clientaddr

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// HeaderXForwardedFor is the list header read by default.
const HeaderXForwardedFor = "X-Forwarded-For"

// Named single-value headers, for Config.Header.
const (
	HeaderCFConnectingIP = "CF-Connecting-IP"
	HeaderTrueClientIP   = "True-Client-IP"
	HeaderXRealIP        = "X-Real-IP"
)

// LoopbackNetworks are the IPv4 and IPv6 loopback networks: the addresses a
// reverse proxy on the same host connects from.
var LoopbackNetworks = []string{"127.0.0.0/8", "::1/128"}

// Config says which proxies to believe and which header they write. The
// zero Config trusts no proxy: every request is attributed to its direct
// peer.
type Config struct {
	// TrustedProxies are the networks, in CIDR notation or as single
	// addresses, of the proxies whose header is believed. A request from
	// any other peer is attributed to the peer.
	TrustedProxies []string `json:"trusted_proxies,omitempty" yaml:"trusted_proxies,omitempty" jsonschema:"description=Networks (CIDR or single addresses) of the reverse proxies whose client-address header is believed; empty trusts no proxy and uses the direct peer"`

	// Header is the header the trusted proxies write the client's address
	// to: X-Forwarded-For (the default), read from the right, or a
	// single-value header such as CF-Connecting-IP or X-Real-IP.
	Header string `json:"header,omitempty" yaml:"header,omitempty" jsonschema:"default=X-Forwarded-For,description=Header the trusted proxies write the client address to: X-Forwarded-For (read from the right) or a single-value header such as CF-Connecting-IP"`
}

// LoopbackProxy is the Config for a reverse proxy on the same host that
// sets X-Forwarded-For.
func LoopbackProxy() Config {
	return Config{TrustedProxies: append([]string(nil), LoopbackNetworks...), Header: HeaderXForwardedFor}
}

// IsZero reports whether the Config trusts no proxy.
func (c Config) IsZero() bool { return len(c.TrustedProxies) == 0 }

// Validate reports whether the networks and the header are well formed.
func (c Config) Validate() error {
	_, err := New(c)
	return err
}

// Resolver finds a request's client address. A nil *Resolver, like the
// zero Config, attributes every request to its direct peer.
type Resolver struct {
	trusted []netip.Prefix
	header  string
	list    bool
}

// Peer returns a Resolver that trusts no proxy.
func Peer() *Resolver { return &Resolver{} }

// New builds a Resolver from cfg. A Header without TrustedProxies is an
// error: it would never be read, which is almost always a mistake in the
// configuration.
func New(cfg Config) (*Resolver, error) {
	trusted, err := ParseNetworks(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	header := strings.TrimSpace(cfg.Header)
	if header == "" {
		header = HeaderXForwardedFor
	} else if len(trusted) == 0 {
		return nil, fmt.Errorf("clientaddr: header %q is set without trusted proxies, so it would never be read", header)
	}
	if strings.ContainsAny(header, " \t,:") {
		return nil, fmt.Errorf("clientaddr: invalid header name %q", header)
	}
	header = http.CanonicalHeaderKey(header)
	return &Resolver{trusted: trusted, header: header, list: header == HeaderXForwardedFor}, nil
}

// MustNew is New for configurations known to be valid, such as literals.
// It panics on an invalid Config.
func MustNew(cfg Config) *Resolver {
	r, err := New(cfg)
	if err != nil {
		panic(err)
	}
	return r
}

// ParseNetworks parses networks in CIDR notation or single addresses
// (taken as /32 or /128). IPv4-mapped IPv6 networks are unmapped.
func ParseNetworks(networks []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(networks))
	for _, n := range networks {
		n = strings.TrimSpace(n)
		if n == "" {
			return nil, errors.New("clientaddr: empty trusted proxy network")
		}
		if strings.Contains(n, "/") {
			p, err := netip.ParsePrefix(n)
			if err != nil {
				return nil, fmt.Errorf("clientaddr: trusted proxy network %q: %w", n, err)
			}
			if p.Addr().Is4In6() {
				p = netip.PrefixFrom(p.Addr().Unmap(), max(p.Bits()-96, 0))
			}
			prefixes = append(prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(n)
		if err != nil {
			return nil, fmt.Errorf("clientaddr: trusted proxy network %q: %w", n, err)
		}
		a = a.Unmap()
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	return prefixes, nil
}

// Header is the header the Resolver reads from trusted proxies, in
// canonical form (http.CanonicalHeaderKey), or "" when it trusts none.
func (r *Resolver) Header() string {
	if r == nil || len(r.trusted) == 0 {
		return ""
	}
	return r.header
}

// TrustsProxies reports whether any proxy network is trusted.
func (r *Resolver) TrustsProxies() bool { return r != nil && len(r.trusted) > 0 }

// Trusted reports whether addr is in one of the trusted proxy networks.
func (r *Resolver) Trusted(addr netip.Addr) bool {
	if r == nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range r.trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// TrustsPeer reports whether the request's direct peer is a trusted proxy.
func (r *Resolver) TrustsPeer(req *http.Request) bool {
	peer, ok := PeerAddr(req)
	return ok && r.Trusted(peer)
}

// Addr returns the request's client address. It reports false only when
// the direct peer's address cannot be parsed.
func (r *Resolver) Addr(req *http.Request) (netip.Addr, bool) {
	a, _, ok := r.resolve(req)
	return a, ok
}

// FromHeader returns the client address the trusted proxy's header names,
// and false when the peer is not trusted or the header names nothing
// usable, so callers can try other sources before the peer.
func (r *Resolver) FromHeader(req *http.Request) (netip.Addr, bool) {
	a, fromHeader, ok := r.resolve(req)
	return a, ok && fromHeader
}

// ClientIP returns the request's client address as a string, or "" when
// the direct peer's address cannot be parsed.
func (r *Resolver) ClientIP(req *http.Request) string {
	a, ok := r.Addr(req)
	if !ok {
		return ""
	}
	return a.String()
}

// resolve returns the client address and whether it came from the header.
func (r *Resolver) resolve(req *http.Request) (addr netip.Addr, fromHeader, ok bool) {
	peer, ok := PeerAddr(req)
	if !ok {
		return netip.Addr{}, false, false
	}
	if r == nil || !r.Trusted(peer) {
		return peer, false, true
	}
	values := req.Header.Values(r.header)
	if len(values) == 0 {
		return peer, false, true
	}
	if !r.list {
		// A single-value header holds exactly one address; several
		// copies or a list mean something other than the proxy wrote it.
		if len(values) != 1 {
			return peer, false, true
		}
		a, err := parseHop(values[0])
		if err != nil {
			return peer, false, true
		}
		return a, true, true
	}
	hops := strings.Split(strings.Join(values, ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop, err := parseHop(hops[i])
		if err != nil {
			// Garbage in the chain: stop believing it.
			return peer, false, true
		}
		if !r.Trusted(hop) {
			return hop, true, true
		}
	}
	// Every hop is a trusted proxy: the request started inside.
	return peer, false, true
}

// parseHop parses one address from a forwarding header. Proxies write bare
// addresses, but some add a port ("192.0.2.1:443", "[2001:db8::1]:443"),
// which is removed.
func parseHop(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return netip.Addr{}, fmt.Errorf("clientaddr: zoned address %q", s)
		}
		return a.Unmap(), nil
	}
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("clientaddr: invalid address %q", s)
	}
	if ap.Addr().Zone() != "" {
		return netip.Addr{}, fmt.Errorf("clientaddr: zoned address %q", s)
	}
	return ap.Addr().Unmap(), nil
}

// PeerAddr returns the address of the request's direct peer, with the port
// and any IPv6 zone removed and IPv4-mapped IPv6 addresses unmapped. It
// reports false when RemoteAddr is not an address.
func PeerAddr(req *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		// A bare address, as some servers and tests set.
		host = strings.Trim(strings.TrimSpace(req.RemoteAddr), "[]")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// PeerIP returns the direct peer's address as a string, or "" when
// RemoteAddr is not an address.
func PeerIP(req *http.Request) string {
	a, ok := PeerAddr(req)
	if !ok {
		return ""
	}
	return a.String()
}
