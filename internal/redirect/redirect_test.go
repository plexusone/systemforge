package redirect

import (
	"net/url"
	"testing"
)

func TestPathIsPlain(t *testing.T) {
	for raw, want := range map[string]bool{
		"/":                           true,
		"/orgs/a?tab=2#x":             true,
		"/files/report.v2.pdf":        true,
		"/a/...":                      true,
		"https://app.example.com/x":   true,
		"/.//evil.example/x":          false,
		"/a/..//evil.example":         false,
		"/%2e//evil.example":          false,
		"/%2E%2E/admin":               false,
		"/a/./b":                      false,
		"/%2F%2Fevil.example":         false,
		"https://app.example.com/./x": false,
		"/a/%zz":                      false,
	} {
		u, err := url.Parse(raw)
		if err != nil {
			// "%zz" is rejected by url.Parse itself; that also refuses it.
			if want {
				t.Fatalf("parse %q: %v", raw, err)
			}
			continue
		}
		if got := PathIsPlain(u); got != want {
			t.Errorf("PathIsPlain(%q) = %v, want %v", raw, got, want)
		}
	}
}
