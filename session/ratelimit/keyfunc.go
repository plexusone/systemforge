package ratelimit

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/session/clientaddr"
	"github.com/plexusone/systemforge/session/middleware"
)

// Common key function builders for rate limiting based on JWT claims.

// PrincipalKey returns a KeyFunc that extracts the principal ID from JWT claims.
// Falls back to IP address if no principal is authenticated.
func PrincipalKey() KeyFunc {
	return func(r *http.Request) string {
		principalID := middleware.PrincipalIDFromContext(r.Context())
		if principalID != uuid.Nil {
			return "pid:" + principalID.String()
		}
		// Fallback to IP for unauthenticated requests
		return "ip:" + extractIP(r)
	}
}

// ClientKey returns a KeyFunc that extracts the OAuth client ID (azp) from JWT claims.
// Falls back to IP address if no client ID is present.
func ClientKey() KeyFunc {
	return func(r *http.Request) string {
		claims := middleware.ClaimsFromContext(r.Context())
		if claims != nil && claims.ClientID != "" {
			return "client:" + claims.ClientID
		}
		// Fallback to IP for requests without client ID
		return "ip:" + extractIP(r)
	}
}

// CompositeKey returns a KeyFunc that combines principal and client IDs.
// Format: "pid:{principal_id}:client:{client_id}" or fallback to IP.
func CompositeKey() KeyFunc {
	return func(r *http.Request) string {
		claims := middleware.ClaimsFromContext(r.Context())
		if claims == nil {
			return "ip:" + extractIP(r)
		}

		var key string
		if claims.PrincipalID != uuid.Nil {
			key = "pid:" + claims.PrincipalID.String()
		}
		if claims.ClientID != "" {
			if key != "" {
				key += ":"
			}
			key += "client:" + claims.ClientID
		}
		if key == "" {
			return "ip:" + extractIP(r)
		}
		return key
	}
}

// EndpointKey wraps another KeyFunc to add endpoint-specific rate limiting.
// Format: "{inner_key}:path:{path}:method:{method}"
func EndpointKey(inner KeyFunc) KeyFunc {
	return func(r *http.Request) string {
		key := inner(r)
		return key + ":path:" + r.URL.Path + ":method:" + r.Method
	}
}

// PrincipalEndpointKey is a convenience function combining PrincipalKey with EndpointKey.
func PrincipalEndpointKey() KeyFunc {
	return EndpointKey(PrincipalKey())
}

// ClientEndpointKey is a convenience function combining ClientKey with EndpointKey.
func ClientEndpointKey() KeyFunc {
	return EndpointKey(ClientKey())
}

// IPKey returns a KeyFunc that keys on the IP address of the direct peer
// (see PeerIP). Behind a reverse proxy every client would share the
// proxy's address; use ForwardedIPKey there. Forwarding headers are never
// believed unless a trusted proxy is configured, because any client can
// send them.
func IPKey() KeyFunc {
	return func(r *http.Request) string {
		return "ip:" + extractIP(r)
	}
}

// ForwardedIPKey is IPKey for a server behind reverse proxies: it takes the
// client address from X-Forwarded-For when the request arrives from one
// of the trusted proxy networks (see ForwardedClientIP).
//
// Deprecated: use AddressKey with a clientaddr.Resolver, the client-address
// rule shared with SystemAuth and the BFF.
func ForwardedIPKey(trustedProxies ...string) (KeyFunc, error) {
	clientIP, err := ForwardedClientIP(trustedProxies...)
	if err != nil {
		return nil, err
	}
	return func(r *http.Request) string {
		return "ip:" + clientIP(r)
	}, nil
}

// AddressKey returns a KeyFunc that keys on the client address res finds
// (see clientaddr). A nil res keys on the direct peer, as IPKey does. An
// unparseable peer address shares one bucket rather than escaping limits.
func AddressKey(res *clientaddr.Resolver) KeyFunc {
	return func(r *http.Request) string {
		return "ip:" + addressOf(res, r)
	}
}

// addressOf is the client address res finds, or "unknown".
func addressOf(res *clientaddr.Resolver, r *http.Request) string {
	if ip := res.ClientIP(r); ip != "" {
		return ip
	}
	return "unknown"
}

// extractIP is the address requests are limited by when no trusted proxy
// is configured: the direct peer's. An unparseable peer address shares one
// bucket rather than escaping limiting.
func extractIP(r *http.Request) string {
	if ip := PeerIP(r); ip != "" {
		return ip
	}
	return "unknown"
}
