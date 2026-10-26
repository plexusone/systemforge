package contract

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func newFederatedTestAPI(t *testing.T, appID string) *API {
	t.Helper()
	provider, err := NewProvider(&Config{AppID: appID, DisplayName: appID, Version: "1.0.0", BaseURL: "/systemforge"}, nil)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	api, err := NewAPI(provider)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	provider.FederationState().SetFederated(uuid.New())
	return api
}

// Each application's contract API keeps its own audit stream state: a
// token allowed to configure one application's stream cannot repoint,
// disable, or acknowledge another's.
func TestAuditStreamStateIsPerAPI(t *testing.T) {
	ctx := WithPermissions(context.Background(), []string{PermissionAuditConfig})
	a := newFederatedTestAPI(t, "app-a")
	b := newFederatedTestAPI(t, "app-b")

	in := &UpdateAuditStreamConfigInput{}
	in.Body.Enabled = true
	in.Body.Endpoint = "https://collector.example.com/a"
	if _, err := a.updateAuditStreamConfig(ctx, in); err != nil {
		t.Fatalf("update a: %v", err)
	}
	if !a.IsAuditStreamEnabled() || a.AuditStreamConfig().Endpoint != "https://collector.example.com/a" {
		t.Errorf("a's config = %+v", a.AuditStreamConfig())
	}
	if b.IsAuditStreamEnabled() || b.AuditStreamConfig().Endpoint != "" {
		t.Errorf("b's config changed with a's: %+v", b.AuditStreamConfig())
	}

	if seq := a.RecordAuditEvent(); seq != 1 {
		t.Errorf("a's first sequence = %d", seq)
	}
	if seq := b.RecordAuditEvent(); seq != 1 {
		t.Errorf("b's first sequence = %d, want its own counter", seq)
	}
	out, err := b.getAuditStreamConfig(ctx, nil)
	if err != nil {
		t.Fatalf("get b: %v", err)
	}
	if out.Body.LastSequence != 1 || out.Body.Enabled {
		t.Errorf("b's reported config = %+v", out.Body)
	}
}
