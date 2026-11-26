package systemauth

import (
	"strings"
	"testing"
)

func TestSignInMethods(t *testing.T) {
	var none *SocialLoginConfig
	if got := none.SignInMethods(); got != nil {
		t.Errorf("nil config: %v", got)
	}
	cfg := &SocialLoginConfig{
		GitHub: &SocialProviderConfig{ClientID: "a", ClientSecret: "b"},
		Email:  &EmailLoginConfig{},
	}
	if got := strings.Join(cfg.SignInMethods(), ","); got != "github,email" {
		t.Errorf("config methods = %q, want github,email", got)
	}
	cfg.Google = &SocialProviderConfig{ClientID: "c", ClientSecret: "d"}
	if got := strings.Join(cfg.SignInMethods(), ","); got != "github,google,email" {
		t.Errorf("config methods = %q, want github,google,email", got)
	}

	// The server's list is what its sign-in page offers.
	s, _ := newEmailLoginServer(t, nil, nil, nil)
	if got := strings.Join(s.SignInMethods(), ","); got != "email" {
		t.Errorf("email-only server = %q, want email", got)
	}
	f := newFakeGitHub(t)
	both, _ := newMailSocialTestServer(t, f, NewMemoryPrincipalDirectory(), nil)
	if got := strings.Join(both.SignInMethods(), ","); got != "github" {
		t.Errorf("github server = %q, want github", got)
	}
	noLogin, err := NewEmbedded(Config{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if got := noLogin.SignInMethods(); got != nil {
		t.Errorf("server without browser sign-in = %v, want nil", got)
	}
}
