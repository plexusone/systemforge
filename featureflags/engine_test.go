package featureflags_test

import (
	"context"
	"testing"

	"github.com/plexusone/systemforge/featureflags"
	"github.com/plexusone/systemforge/featureflags/stores"
)

// A flag limited to targets or a partial rollout must stay off when there
// is no subject to evaluate it for.
func TestRestrictedFlagIsOffWithoutSubject(t *testing.T) {
	ctx := context.Background()
	engine := featureflags.NewEngine(stores.NewMemoryStore())
	flags := []*featureflags.Flag{
		{Key: "targeted", Enabled: true, Targets: []string{"user-1"}},
		{Key: "rollout", Enabled: true, Percentage: 10},
		{Key: "targeted-rollout", Enabled: true, Targets: []string{"org-a"}, Percentage: 50},
	}
	for _, f := range flags {
		if err := engine.SetFlag(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range flags {
		for name, evalCtx := range map[string]*featureflags.EvaluationContext{
			"nil":   nil,
			"empty": {},
		} {
			on, err := engine.IsEnabled(ctx, f.Key, evalCtx)
			if err != nil {
				t.Fatal(err)
			}
			if on {
				t.Errorf("%s with %s context: enabled, want disabled", f.Key, name)
			}
		}
		on, err := engine.IsEnabledSimple(ctx, f.Key)
		if err != nil {
			t.Fatal(err)
		}
		if on {
			t.Errorf("%s with IsEnabledSimple: enabled, want disabled", f.Key)
		}
	}

	on, err := engine.IsEnabled(ctx, "targeted", &featureflags.EvaluationContext{UserID: "user-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !on {
		t.Error("targeted flag is off for its target")
	}
}

// An unrestricted flag keeps its global state without a subject.
func TestUnrestrictedFlagFollowsGlobalStateWithoutSubject(t *testing.T) {
	ctx := context.Background()
	engine := featureflags.NewEngine(stores.NewMemoryStore())
	for _, f := range []*featureflags.Flag{
		{Key: "global", Enabled: true},
		{Key: "full-rollout", Enabled: true, Percentage: 100, Targets: []string{"user-1"}},
	} {
		if err := engine.SetFlag(ctx, f); err != nil {
			t.Fatal(err)
		}
		on, err := engine.IsEnabledSimple(ctx, f.Key)
		if err != nil {
			t.Fatal(err)
		}
		if !on {
			t.Errorf("%s: disabled, want enabled", f.Key)
		}
	}
}
