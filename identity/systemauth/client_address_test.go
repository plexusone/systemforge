package systemauth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/session/clientaddr"
)

// TestClientAddressFromConfig verifies that client_address configures the
// resolver every part of the server uses, and that a forwarding header
// from a peer that is not a trusted proxy is ignored.
func TestClientAddressFromConfig(t *testing.T) {
	s, err := NewEmbedded(Config{Issuer: testIssuer, ClientAddress: clientaddr.LoopbackProxy()})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-For", "192.0.2.1, 203.0.113.7")
	if got := s.tokenClientIP(r); got != "203.0.113.7" {
		t.Errorf("behind the proxy: %q, want 203.0.113.7", got)
	}
	r.RemoteAddr = "198.51.100.2:4000"
	if got := s.tokenClientIP(r); got != "198.51.100.2" {
		t.Errorf("from an untrusted peer: %q, want the peer", got)
	}
}

// TestClientAddressDefaultIsThePeer verifies that without client_address
// no header is believed.
func TestClientAddressDefaultIsThePeer(t *testing.T) {
	s, err := NewEmbedded(Config{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	r.RemoteAddr = "127.0.0.1:4000"
	r.Header.Set("X-Forwarded-For", "203.0.113.7")
	if got := s.ClientAddress().ClientIP(r); got != "127.0.0.1" {
		t.Errorf("ClientIP = %q, want the peer", got)
	}
}

// TestClientAddressOptionAndDeprecatedOverride verifies that
// WithClientAddressResolver replaces the configuration and that the
// deprecated WithLoginTokenClientIP still takes precedence.
func TestClientAddressOptionAndDeprecatedOverride(t *testing.T) {
	res := clientaddr.MustNew(clientaddr.Config{TrustedProxies: []string{"10.0.0.0/8"}, Header: clientaddr.HeaderCFConnectingIP})
	s, err := NewEmbedded(Config{Issuer: testIssuer}, WithClientAddressResolver(res))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/oauth/token", nil)
	r.RemoteAddr = "10.1.1.1:4000"
	r.Header.Set("CF-Connecting-IP", "203.0.113.8")
	if got := s.tokenClientIP(r); got != "203.0.113.8" {
		t.Errorf("resolver option: %q", got)
	}
	s, err = NewEmbedded(Config{Issuer: testIssuer}, WithClientAddressResolver(res),
		WithLoginTokenClientIP(func(*http.Request) string { return "192.0.2.99" }))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if got := s.tokenClientIP(r); got != "192.0.2.99" {
		t.Errorf("deprecated override: %q", got)
	}
}

func TestClientAddressInvalidConfig(t *testing.T) {
	_, err := NewEmbedded(Config{Issuer: testIssuer, ClientAddress: clientaddr.Config{TrustedProxies: []string{"not-a-network"}}})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewEmbedded = %v, want ErrInvalidConfig", err)
	}
}
