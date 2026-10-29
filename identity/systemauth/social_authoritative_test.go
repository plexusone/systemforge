package systemauth

import (
	"testing"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

func TestAuthoritativeEmail(t *testing.T) {
	google := func(email, hd string, verified bool) *oauthclient.User {
		return &oauthclient.User{Provider: oauthclient.ProviderGoogle, Email: email, HostedDomain: hd, EmailVerified: verified}
	}
	tests := []struct {
		name string
		user *oauthclient.User
		want bool
	}{
		{"gmail", google("ada@gmail.com", "", true), true},
		{"googlemail, mixed case", google("Ada@GoogleMail.com", "", true), true},
		{"workspace domain matches hd", google("ada@corp.example", "corp.example", true), true},
		{"workspace hd case-insensitive", google("ada@Corp.Example", "corp.example", true), true},
		{"non-gmail consumer account", google("ada@corp.example", "", true), false},
		{"hd for another domain", google("ada@other.example", "corp.example", true), false},
		{"subdomain is not the hd", google("ada@mail.corp.example", "corp.example", true), false},
		{"unverified gmail", google("ada@gmail.com", "", false), false},
		{"github verified", &oauthclient.User{Provider: oauthclient.ProviderGitHub, Email: "ada@gmail.com", EmailVerified: true}, false},
		{"no domain", google("ada@", "", true), false},
		{"no at sign", google("ada", "", true), false},
		{"nil user", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AuthoritativeEmail(tt.user); got != tt.want {
				t.Errorf("AuthoritativeEmail = %v, want %v", got, tt.want)
			}
		})
	}
}
