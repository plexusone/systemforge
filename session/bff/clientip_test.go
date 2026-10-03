package bff

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPExtractor_GetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		config     ClientIPConfig
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no trust - uses RemoteAddr",
			config:     DefaultClientIPConfig(),
			remoteAddr: "192.168.1.100:54321",
			headers: map[string]string{
				"X-Forwarded-For":  "10.0.0.1",
				"CF-Connecting-IP": "1.2.3.4",
			},
			want: "192.168.1.100",
		},
		{
			name:       "trust cloudflare - uses CF-Connecting-IP",
			config:     CloudflareClientIPConfig(),
			remoteAddr: "172.16.0.1:54321",
			headers: map[string]string{
				"CF-Connecting-IP": "203.0.113.50",
				"X-Forwarded-For":  "203.0.113.50, 172.16.0.1",
			},
			want: "203.0.113.50",
		},
		{
			name:       "trust cloudflare - uses True-Client-IP when CF-Connecting-IP missing",
			config:     CloudflareClientIPConfig(),
			remoteAddr: "172.16.0.1:54321",
			headers: map[string]string{
				"True-Client-IP": "198.51.100.25",
			},
			want: "198.51.100.25",
		},
		{
			name: "trust proxy - uses X-Real-IP",
			config: ClientIPConfig{
				TrustProxy: true,
			},
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Real-IP": "203.0.113.100",
			},
			want: "203.0.113.100",
		},
		{
			name: "trust proxy - uses X-Forwarded-For first IP",
			config: ClientIPConfig{
				TrustProxy: true,
			},
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.100, 10.0.0.2, 10.0.0.1",
			},
			want: "203.0.113.100",
		},
		{
			name: "trusted proxy ranges - skips trusted proxies in XFF",
			config: ClientIPConfig{
				TrustProxy:     true,
				TrustedProxies: []string{"10.0.0.0/8"},
			},
			remoteAddr: "10.0.0.1:54321",
			headers: map[string]string{
				"X-Forwarded-For": "203.0.113.100, 10.0.0.2, 10.0.0.1",
			},
			want: "203.0.113.100",
		},
		{
			name:       "IPv6 RemoteAddr",
			config:     DefaultClientIPConfig(),
			remoteAddr: "[::1]:54321",
			want:       "::1",
		},
		{
			name:       "IPv6 RemoteAddr no port",
			config:     DefaultClientIPConfig(),
			remoteAddr: "::1",
			want:       "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := NewClientIPExtractor(tt.config)

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			got := extractor.GetClientIP(req)
			if got != tt.want {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetCloudflareMetadata(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("CF-Ray", "abc123-SJC")
	req.Header.Set("CF-IPCountry", "US")
	req.Header.Set("CF-Visitor", `{"scheme":"https"}`)

	meta := GetCloudflareMetadata(req)

	if meta["cf_ray"] != "abc123-SJC" {
		t.Errorf("cf_ray = %q, want %q", meta["cf_ray"], "abc123-SJC")
	}
	if meta["cf_country"] != "US" {
		t.Errorf("cf_country = %q, want %q", meta["cf_country"], "US")
	}
	if meta["cf_visitor"] != `{"scheme":"https"}` {
		t.Errorf("cf_visitor = %q, want %q", meta["cf_visitor"], `{"scheme":"https"}`)
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"192.168.1.1:8080", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"::1", "::1"},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			got := extractIP(tt.addr)
			if got != tt.want {
				t.Errorf("extractIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestClientIPExtractor_CloudflareIPRanges(t *testing.T) {
	config := ClientIPConfig{
		TrustCloudflare: true,
		// Only trust requests from this specific range
		CloudflareIPRanges: []string{"172.16.0.0/12"},
	}
	extractor := NewClientIPExtractor(config)

	// Request from trusted Cloudflare range
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "172.16.0.1:54321"
	req1.Header.Set("CF-Connecting-IP", "203.0.113.50")

	got1 := extractor.GetClientIP(req1)
	if got1 != "203.0.113.50" {
		t.Errorf("Trusted CF range: got %q, want %q", got1, "203.0.113.50")
	}

	// Request from untrusted range - CF header should be ignored
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.1:54321"
	req2.Header.Set("CF-Connecting-IP", "203.0.113.50")

	got2 := extractor.GetClientIP(req2)
	if got2 != "192.168.1.1" {
		t.Errorf("Untrusted range: got %q, want %q", got2, "192.168.1.1")
	}
}
