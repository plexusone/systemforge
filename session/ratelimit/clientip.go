package ratelimit

import (
	"errors"
	"net/http"

	"github.com/plexusone/systemforge/session/clientaddr"
)

// PeerIP returns the IP address of the connection's direct peer, with the
// port removed and IPv4-mapped IPv6 addresses unmapped. It is the one
// address a client cannot choose, so it is what limits key on by default.
// It returns "" when the peer address cannot be parsed. It is
// clientaddr.PeerIP.
func PeerIP(r *http.Request) string {
	return clientaddr.PeerIP(r)
}

// ForwardedClientIP returns a function that finds the client's address
// behind reverse proxies. When the direct peer is one of the trusted
// proxy networks, it reads X-Forwarded-For from the right, skipping
// addresses that are themselves trusted proxies, and returns the first
// address a trusted proxy did not vouch for. Requests whose peer is not a
// trusted proxy, or whose header holds nothing usable, are attributed to
// the peer itself.
//
// Deprecated: build a clientaddr.Resolver, which also reads single-value
// headers such as CF-Connecting-IP, and pass its ClientIP method, or key
// limits with AddressKey.
func ForwardedClientIP(trustedProxies ...string) (func(*http.Request) string, error) {
	if len(trustedProxies) == 0 {
		return nil, errors.New("ratelimit: no trusted proxy networks given")
	}
	res, err := clientaddr.New(clientaddr.Config{TrustedProxies: trustedProxies})
	if err != nil {
		return nil, err
	}
	return res.ClientIP, nil
}
