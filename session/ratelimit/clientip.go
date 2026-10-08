package ratelimit

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// PeerIP returns the IP address of the connection's direct peer, with the
// port removed and IPv4-mapped IPv6 addresses unmapped. It is the one
// address a client cannot choose, so it is what limits key on by default.
// It returns "" when the peer address cannot be parsed.
func PeerIP(r *http.Request) string {
	addr, ok := peerAddr(r)
	if !ok {
		return ""
	}
	return addr.String()
}

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// A bare address, as some servers and tests set.
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// ForwardedClientIP returns a function that finds the client's address
// behind reverse proxies. When the direct peer is one of the trusted
// proxy networks, it reads X-Forwarded-For from the right, skipping
// addresses that are themselves trusted proxies, and returns the first
// address a trusted proxy did not vouch for: a client can put anything at
// the left of the header, but not past the proxy that appends to it.
// Requests whose peer is not a trusted proxy, or whose header holds
// nothing usable, are attributed to the peer itself.
func ForwardedClientIP(trustedProxies ...string) (func(*http.Request) string, error) {
	if len(trustedProxies) == 0 {
		return nil, errors.New("ratelimit: no trusted proxy networks given")
	}
	prefixes := make([]netip.Prefix, 0, len(trustedProxies))
	for _, c := range trustedProxies {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("ratelimit: trusted proxy network %q: %w", c, err)
		}
		prefixes = append(prefixes, p)
	}
	trusted := func(a netip.Addr) bool {
		for _, p := range prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	return func(r *http.Request) string {
		peer, ok := peerAddr(r)
		if !ok {
			return ""
		}
		if !trusted(peer) {
			return peer.String()
		}
		hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
		for i := len(hops) - 1; i >= 0; i-- {
			hop, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
			if err != nil {
				return peer.String() // garbage in the chain: stop trusting it
			}
			hop = hop.Unmap()
			if !trusted(hop) {
				return hop.String()
			}
		}
		return peer.String()
	}, nil
}
