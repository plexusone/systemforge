package oauthclient

import "testing"

func TestSelectGitHubEmailPrimaryOnly(t *testing.T) {
	tests := []struct {
		name         string
		emails       []githubEmail
		want         string
		wantVerified bool
	}{
		{"primary verified", []githubEmail{{Email: "old@corp.example", Verified: true}, {Email: "me@example.com", Primary: true, Verified: true}}, "me@example.com", true},
		{"primary unverified, other verified", []githubEmail{{Email: "old@corp.example", Verified: true}, {Email: "me@example.com", Primary: true}}, "me@example.com", false},
		{"no primary", []githubEmail{{Email: "old@corp.example", Verified: true}}, "", false},
		{"none", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, verified := selectGitHubEmail(tt.emails)
			if got != tt.want || verified != tt.wantVerified {
				t.Errorf("selectGitHubEmail = %q, %v; want %q, %v", got, verified, tt.want, tt.wantVerified)
			}
		})
	}
}
