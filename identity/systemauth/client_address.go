package systemauth

import (
	"fmt"
	"net/http"

	"github.com/plexusone/systemforge/session/clientaddr"
)

// WithClientAddressResolver sets how the server finds a request's client
// address, for rate limits and the addresses it records, in place of the
// configuration's client_address. Share one Resolver with the BFF, appauth
// and the application's rate limits so they agree on who a client is.
func WithClientAddressResolver(res *clientaddr.Resolver) Option {
	return func(s *Server) { s.clientAddr = res }
}

// setupClientAddress builds the client-address resolver from the
// configuration unless an option supplied one.
func (s *Server) setupClientAddress() error {
	if s.clientAddr != nil {
		return nil
	}
	res, err := clientaddr.New(s.config.ClientAddress)
	if err != nil {
		return fmt.Errorf("%w: client_address: %v", ErrInvalidConfig, err)
	}
	s.clientAddr = res
	return nil
}

// ClientAddress returns the server's client-address resolver.
func (s *Server) ClientAddress() *clientaddr.Resolver { return s.clientAddr }

// clientIP is a request's client address: as WithLoginTokenClientIP finds
// it when that deprecated option is set, otherwise as the client-address
// resolver does. It is "" only when the direct peer cannot be parsed.
func (s *Server) clientIP(r *http.Request) string {
	if f := s.socialOpts.loginTokenClientIP; f != nil {
		return f(r)
	}
	return s.clientAddr.ClientIP(r)
}

// tokenClientIP is the address of a token request's client.
func (s *Server) tokenClientIP(r *http.Request) string { return s.clientIP(r) }
