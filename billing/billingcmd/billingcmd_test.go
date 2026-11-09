package billingcmd_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"

	"github.com/plexusone/systemforge/billing/billingcmd"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func TestSyncInFreeModeSaysSo(t *testing.T) {
	spec, err := pricingspec.Load(strings.NewReader(`{"formatVersion":"1","app":"a","currency":"usd","defaultPlan":"free",
		"applications":[{"id":"a","name":"A"}],"tiers":[{"id":"free","name":"Free","rank":1}],
		"plans":[{"id":"free","name":"Free","tier":"free","selfServe":true}],
		"entitlements":[{"tier":"free","application":"a","seats":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	cmd := billingcmd.Command(func(context.Context) (*systemauthsvc.Config, *pricingspec.Spec, error) {
		return &systemauthsvc.Config{Billing: &systemauth.BillingConfig{}}, spec, nil
	})
	cmd.SetArgs([]string{"sync", "--dry-run"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.ExecuteContext(t.Context()); !errors.Is(err, systemauthsvc.ErrBillingNotConfigured) {
		t.Fatalf("sync without a key: %v", err)
	}
}
