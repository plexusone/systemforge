package audit

import (
	"strings"
	"testing"
)

func TestSanitizeUserAgent(t *testing.T) {
	keep := []string{
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
		"Go-http-client/2.0",
		"curl/8.7.1",
		"systemforge-cli/0.30.0 (darwin; arm64)",
	}
	for _, ua := range keep {
		if got := SanitizeUserAgent(ua); got != ua {
			t.Errorf("%q: got %q, want it kept", ua, got)
		}
	}
	drop := []string{
		"curl/8.7.1 alice@example.com",
		"bot (contact: ops+alerts@example.co.uk)",
		"curl/8 alice@\texample.com",
		"curl/8 alice\x00@example\x7f.com",
		"client eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig",
		"app/1.0 token=" + strings.Repeat("ab", 20),
		"tool/2 c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA==",
	}
	for _, ua := range drop {
		if got := SanitizeUserAgent(ua); got != "" {
			t.Errorf("%q: got %q, want it dropped", ua, got)
		}
	}
	long := strings.Repeat("Mozilla/5.0 ", 100)
	if got := SanitizeUserAgent(long); len(got) != MaxUserAgent {
		t.Errorf("long User-Agent cut to %d bytes, want %d", len(got), MaxUserAgent)
	}
	if got := SanitizeUserAgent("agent/1\x00\n\x7f\xff(x)"); got != "agent/1(x)" {
		t.Errorf("control characters and invalid UTF-8: got %q", got)
	}
}
