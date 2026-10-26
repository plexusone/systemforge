package systemauthsvc_test

import (
	"strings"
	"testing"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// Without configuration the service builds one rbac authorization mode,
// whose syncer writes nothing and which has no graph reconciler.
func TestAuthzDefaultsToRBAC(t *testing.T) {
	svc := scimService(t, &systemauthsvc.SCIMOptions{})
	res := svc.Authz()
	if res == nil || res.Mode != authz.ModeRBAC {
		t.Fatalf("authorization mode = %+v, want rbac", res)
	}
	if _, ok := res.Syncer.(*noop.Syncer); !ok {
		t.Errorf("rbac syncer = %T, want the no-op syncer", res.Syncer)
	}
	if svc.AuthzReconciler() != nil {
		t.Error("rbac has a graph reconciler")
	}
}

// Connections are served in mode rbac only, and the service refuses to
// start otherwise rather than serve them unchecked.
func TestConnectionsRefuseModeReBAC(t *testing.T) {
	cfg := &systemauthsvc.Config{
		Issuer:      mpIssuer,
		Database:    &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Authz:       authz.ModeConfig{Mode: authz.ModeReBAC},
		Connections: &systemauth.ConnectionsConfig{KeysDir: t.TempDir(), Vault: "env://", RootKey: "SF_TEST_UNSET_ROOT_KEY"},
	}
	_, err := systemauthsvc.New(t.Context(), cfg, systemauthsvc.Options{Dev: true, SigningKey: testKey(t), Logger: discardLogger()})
	if err == nil || !strings.Contains(err.Error(), "connections support authz mode") {
		t.Fatalf("New = %v, want the connections mode error", err)
	}
}
