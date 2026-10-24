package aauthrs

import (
	"errors"
	"testing"

	aauth "github.com/aauth-dev/aauth-go"
)

// An agent provider may vouch only for agents of its own domain: a provider
// at attacker.example claiming aauth:billing-bot@victim.example is refused.
func TestAgentBelongsToIssuer(t *testing.T) {
	tests := []struct {
		sub, iss string
		ok       bool
	}{
		{"aauth:billing-bot@agents.example", "https://agents.example", true},
		{"aauth:billing-bot@agents.example", "https://Agents.Example", true},
		{"aauth:billing-bot@Agents.Example", "https://agents.example", false},
		{"aauth:billing-bot+run1@agents.example", "https://agents.example", true},
		{"aauth:billing-bot@victim.example", "https://attacker.example", false},
		{"aauth:billing-bot@agents.example", "https://agents.example.attacker.example", false},
		{"aauth:billing-bot@agents.example", "not a url", false},
		{"billing-bot", "https://agents.example", false},
	}
	for _, tt := range tests {
		err := agentBelongsToIssuer(tt.sub, tt.iss)
		if (err == nil) != tt.ok {
			t.Errorf("agentBelongsToIssuer(%q, %q) = %v, want ok=%v", tt.sub, tt.iss, err, tt.ok)
		}
		if err != nil && !errors.Is(err, aauth.ErrInvalidToken) {
			t.Errorf("agentBelongsToIssuer(%q, %q) error %v does not wrap ErrInvalidToken", tt.sub, tt.iss, err)
		}
	}
}
