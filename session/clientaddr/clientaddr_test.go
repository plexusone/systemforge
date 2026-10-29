package clientaddr

import (
	"net/http/httptest"
	"testing"
)

func TestResolverClientIP(t *testing.T) {
	loopback := LoopbackProxy()
	cf := Config{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderCFConnectingIP}
	chain := Config{TrustedProxies: []string{"10.0.0.0/8", "127.0.0.1"}}
	tests := []struct {
		name    string
		cfg     Config
		remote  string
		headers map[string][]string
		want    string
	}{
		{"zero config ignores headers", Config{}, "198.51.100.7:1234",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9"}, "Cf-Connecting-Ip": {"203.0.113.9"}}, "198.51.100.7"},
		{"untrusted peer is never believed", loopback, "198.51.100.7:1234",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9"}}, "198.51.100.7"},
		{"loopback proxy single entry", loopback, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9"}}, "203.0.113.9"},
		{"spoofed left entries are skipped", loopback, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.9"}}, "203.0.113.9"},
		{"trusted hops skipped from the right", chain, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"1.1.1.1, 203.0.113.9, 10.0.0.2"}}, "203.0.113.9"},
		{"several header lines join", chain, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"1.1.1.1", "203.0.113.9, 10.0.0.2"}}, "203.0.113.9"},
		{"all hops trusted gives the peer", chain, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"10.0.0.3, 10.0.0.2"}}, "127.0.0.1"},
		{"garbage in the chain gives the peer", chain, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9, nonsense"}}, "127.0.0.1"},
		{"no header gives the peer", loopback, "127.0.0.1:5555", nil, "127.0.0.1"},
		{"IPv6 peer and hop", loopback, "[::1]:5555",
			map[string][]string{"X-Forwarded-For": {"2001:db8::1"}}, "2001:db8::1"},
		{"hop with port", loopback, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9:443"}}, "203.0.113.9"},
		{"IPv6 hop with port", loopback, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"[2001:db8::1]:443"}}, "2001:db8::1"},
		{"mapped hop unmapped", loopback, "127.0.0.1:5555",
			map[string][]string{"X-Forwarded-For": {"::ffff:203.0.113.9"}}, "203.0.113.9"},
		{"mapped peer unmapped", loopback, "[::ffff:127.0.0.1]:5555",
			map[string][]string{"X-Forwarded-For": {"203.0.113.9"}}, "203.0.113.9"},
		{"single-value header", cf, "10.1.2.3:443",
			map[string][]string{"Cf-Connecting-Ip": {"203.0.113.9"}, "X-Forwarded-For": {"1.1.1.1"}}, "203.0.113.9"},
		{"single-value header from untrusted peer", cf, "198.51.100.7:443",
			map[string][]string{"Cf-Connecting-Ip": {"203.0.113.9"}}, "198.51.100.7"},
		{"single-value header with a list", cf, "10.1.2.3:443",
			map[string][]string{"Cf-Connecting-Ip": {"1.1.1.1, 203.0.113.9"}}, "10.1.2.3"},
		{"single-value header repeated", cf, "10.1.2.3:443",
			map[string][]string{"Cf-Connecting-Ip": {"1.1.1.1", "203.0.113.9"}}, "10.1.2.3"},
		{"bare peer address", Config{}, "198.51.100.7", nil, "198.51.100.7"},
		{"unparseable peer", Config{}, "not-an-address", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := New(tt.cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for k, vs := range tt.headers {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			if got := res.ClientIP(r); got != tt.want {
				t.Errorf("ClientIP = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNilAndPeerResolver(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	var nilRes *Resolver
	if got := nilRes.ClientIP(r); got != "127.0.0.1" {
		t.Errorf("nil resolver = %q", got)
	}
	if got := Peer().ClientIP(r); got != "127.0.0.1" {
		t.Errorf("Peer resolver = %q", got)
	}
	if nilRes.TrustsPeer(r) || Peer().TrustsProxies() || nilRes.Header() != "" {
		t.Error("a resolver without proxies trusts something")
	}
}

func TestFromHeader(t *testing.T) {
	res := MustNew(LoopbackProxy())
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "127.0.0.1:1"
	if _, ok := res.FromHeader(r); ok {
		t.Error("FromHeader without a header reported an address")
	}
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	if a, ok := res.FromHeader(r); !ok || a.String() != "203.0.113.9" {
		t.Errorf("FromHeader = %v, %v", a, ok)
	}
}

func TestNewErrors(t *testing.T) {
	for _, cfg := range []Config{
		{TrustedProxies: []string{"10.0.0.0/33"}},
		{TrustedProxies: []string{"nonsense"}},
		{TrustedProxies: []string{""}},
		{Header: HeaderCFConnectingIP},
		{TrustedProxies: []string{"10.0.0.0/8"}, Header: "Bad Header"},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
	if err := (Config{TrustedProxies: []string{"10.0.0.1", "::1", "::ffff:10.0.0.0/104"}}).Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestMappedNetwork(t *testing.T) {
	res := MustNew(Config{TrustedProxies: []string{"::ffff:10.0.0.0/104"}})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "10.2.3.4:1"
	if !res.TrustsPeer(r) {
		t.Error("an IPv4-mapped network does not match its IPv4 addresses")
	}
}
