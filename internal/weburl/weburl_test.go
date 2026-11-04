package weburl

import "testing"

func TestCheckHTTPS(t *testing.T) {
	for _, ok := range []string{"", "https://cdn.example.com/a.png", "HTTPS://example.com"} {
		if err := CheckHTTPS(ok); err != nil {
			t.Errorf("CheckHTTPS(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"http://example.com/a.png",
		"//example.com/a.png",
		"/a.png",
		"https://user:pw@example.com/",
		"https://example.com/\nx",
		"https:\\\\example.com",
		"https://" + string(make([]byte, MaxLen)),
	} {
		if err := CheckHTTPS(bad); err == nil {
			t.Errorf("CheckHTTPS(%q) = nil, want an error", bad)
		}
	}
	if got := HTTPSOrEmpty("http://x.example/a.png"); got != "" {
		t.Errorf("HTTPSOrEmpty(http) = %q, want empty", got)
	}
}
