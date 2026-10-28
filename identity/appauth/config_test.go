package appauth

import (
	"reflect"
	"strings"
	"testing"
)

func validConfig(t *testing.T) Config {
	t.Helper()
	key, _ := p256PEM(t, false)
	return Config{
		Issuer: "https://auth.example.com", ClientID: "app",
		PublicURL: "https://app.example.com", DPoPKey: key,
	}
}

func TestValidate(t *testing.T) {
	if err := validConfig(t).Validate(DefaultLabels); err != nil {
		t.Fatalf("valid: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{"no issuer", func(c *Config) { c.Issuer = "" }, "issuer is required"},
		{"relative issuer", func(c *Config) { c.Issuer = "auth.example.com" }, `issuer must be an absolute URL, got "auth.example.com"`},
		{"http issuer", func(c *Config) { c.Issuer = "http://auth.example.com" }, "issuer must use https (http is allowed only for a loopback host)"},
		{"ftp issuer", func(c *Config) { c.Issuer = "ftp://auth.example.com" }, "issuer must be an http(s) URL"},
		{"no client", func(c *Config) { c.ClientID = "" }, "client ID is required"},
		{"no public URL", func(c *Config) { c.PublicURL = "" }, "public URL is required"},
		{"public URL path", func(c *Config) { c.PublicURL = "https://app.example.com/app" }, "public URL must be an origin without a path"},
		{"origin path", func(c *Config) { c.AllowedOrigins = []string{"https://x.example.com/p"} }, "allowed origin must be an origin without a path"},
		{"empty accepted client", func(c *Config) { c.AcceptedClientIDs = []string{" "} }, "accepted client ID must not be empty"},
		{"no key", func(c *Config) { c.DPoPKey = "" }, "DPoP key is required (generate one with " + DPoPKeyCommand + ")"},
		{"bad key", func(c *Config) { c.DPoPKey = "nope" }, "DPoP key: not a PEM private key"},
		{"key and file", func(c *Config) { c.DPoPKeyFile = "/k.pem" }, "DPoP key and DPoP key file are both set"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validConfig(t)
			tc.mutate(&c)
			err := c.Validate(DefaultLabels)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("got %v, want %q", err, tc.want)
			}
		})
	}

	// Loopback hosts may use http.
	c := validConfig(t)
	c.Issuer, c.PublicURL = "http://127.0.0.1:9000", "http://app.localhost:8080"
	if err := c.Validate(DefaultLabels); err != nil {
		t.Errorf("loopback: %v", err)
	}

	// Every problem is reported.
	if err := (Config{}).Validate(DefaultLabels); err == nil || strings.Count(err.Error(), "\n") < 3 {
		t.Errorf("empty config: %v", err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	key, _ := p256PEM(t, false)
	t.Setenv("APP_SYSTEMAUTH_ISSUER", "https://auth.example.com")
	t.Setenv("APP_CLIENT_ID", "app")
	t.Setenv("APP_PUBLIC_URL", "https://app.example.com")
	t.Setenv("APP_ALLOWED_ORIGINS", " https://a.example.com, ,https://b.example.com")
	t.Setenv("APP_ACCEPTED_CLIENT_IDS", "cli")
	t.Setenv("APP_DPOP_KEY", key)
	cfg, labels := ConfigFromEnv("APP")
	if err := cfg.Validate(labels); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.AllowedOrigins, []string{"https://a.example.com", "https://b.example.com"}) {
		t.Errorf("origins: %v", cfg.AllowedOrigins)
	}
	if labels.Issuer != "Issuer (APP_SYSTEMAUTH_ISSUER)" {
		t.Errorf("label: %q", labels.Issuer)
	}
	cfg.ClientID = ""
	if err := cfg.Validate(labels); err == nil || !strings.Contains(err.Error(), "ClientID (APP_CLIENT_ID) is required") {
		t.Errorf("labelled error: %v", err)
	}
	if !cfg.Configured() || (Config{}).Configured() {
		t.Error("Configured")
	}
}

func TestRedirectURLAndClients(t *testing.T) {
	c := validConfig(t)
	if got := c.RedirectURL(); got != "https://app.example.com/bff/auth/callback" {
		t.Errorf("redirect: %s", got)
	}
	c.BasePath = "auth/"
	if got := c.RedirectURL(); got != "https://app.example.com/auth/auth/callback" {
		t.Errorf("redirect with base path: %s", got)
	}
	if c.acceptedClientIDs() != nil {
		t.Error("no accepted clients should leave the default")
	}
	c.AcceptedClientIDs = []string{"cli"}
	if got := c.acceptedClientIDs(); !reflect.DeepEqual(got, []string{"app", "cli"}) {
		t.Errorf("accepted: %v", got)
	}
	if c.insecureCookies() {
		t.Error("https must use secure cookies")
	}
	c.PublicURL = "http://localhost:8080"
	if !c.insecureCookies() {
		t.Error("loopback http uses insecure cookies")
	}
}
