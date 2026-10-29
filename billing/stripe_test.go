package billing

import (
	"errors"
	"testing"

	"github.com/plexusone/payforge"
	payforgestripe "github.com/plexusone/payforge/stripe"
)

func TestNewStripe(t *testing.T) {
	spec := loadSpec(t)
	good := StripeConfig{
		SecretKey:       "sk_test_fake", //nolint:gosec // G101: a fake key for a test
		WebhookSecrets:  []string{"whsec_a", "whsec_b"},
		AllowedURLHosts: []string{"app.example.com"},
		Locker:          &payforge.MemoryLocker{},
	}
	client, hook, err := NewStripe(spec, good)
	if err != nil {
		t.Fatal(err)
	}
	if client.Mode() != payforgestripe.ModeTest || hook.Mode != payforgestripe.ModeTest || len(hook.Secrets) != 2 {
		t.Fatalf("mode %s, reader %+v", client.Mode(), hook.Mode)
	}

	if _, _, err := NewStripe(spec, StripeConfig{}); !errors.Is(err, payforge.ErrNotConfigured) {
		t.Fatalf("no key: %v", err)
	}
	for name, mutate := range map[string]func(*StripeConfig){
		"one webhook secret for a marketplace": func(c *StripeConfig) { c.WebhookSecrets = c.WebhookSecrets[:1] },
		"no allowed hosts":                     func(c *StripeConfig) { c.AllowedURLHosts = nil },
		"no locker":                            func(c *StripeConfig) { c.Locker = nil },
	} {
		cfg := good
		mutate(&cfg)
		if _, _, err := NewStripe(spec, cfg); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}
