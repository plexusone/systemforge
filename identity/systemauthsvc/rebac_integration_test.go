//go:build integration

package systemauthsvc_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/scim"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// The packaged service runs in mode rebac with an embedded SpiceDB: one
// authorization mode for every part of it, the identity services it
// constructs writing through its syncer, and its reconciler run by RunJobs.
func TestPackagedServiceInModeReBAC(t *testing.T) {
	ctx := context.Background()
	cfg := &systemauthsvc.Config{
		Issuer:   mpIssuer,
		Database: &systemauth.DatabaseConfig{Driver: "sqlite", DSN: sqliteDSN(t)},
		Authz:    authz.ModeConfig{Mode: authz.ModeReBAC},
		Features: systemauth.FeatureConfig{RequirePKCE: true},
	}
	svc, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
		Dev:        true,
		SigningKey: testKey(t),
		Logger:     discardLogger(),
		Migrate:    true,
		SCIM:       &systemauthsvc.SCIMOptions{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	closeService(t, svc)

	res := svc.Authz()
	if res == nil || res.Mode != authz.ModeReBAC || res.Reconciler == nil || svc.AuthzReconciler() != res.Reconciler {
		t.Fatalf("authorization mode = %+v, want rebac with a reconciler", res)
	}
	role := func(p, org uuid.UUID) string {
		t.Helper()
		r, err := res.Provider.GetRole(ctx, authz.NewUserPrincipal(p), org)
		if err != nil {
			t.Fatalf("GetRole: %v", err)
		}
		return r
	}

	// Rows written without the services reach the graph through the
	// reconciler.
	alice := addManager(t, svc, "alice@example.com")
	acme := addOrg(t, svc, "acme", alice)
	if got := role(alice, acme); got != "" {
		t.Fatalf("graph role before reconciling = %q", got)
	}
	if _, err := svc.AuthzReconciler().Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if got := role(alice, acme); got != "owner" {
		t.Fatalf("graph role after reconciling = %q, want owner", got)
	}

	// The SCIM token API authorizes with the shared provider, and SCIM
	// provisioning writes and removes memberships through its syncer.
	tok, err := svc.SCIMTokens().Issue(ctx, alice, acme, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	code, body := scimUsers(t, svc, tok.Token, http.MethodPost, map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "ada@example.com"})
	if code != http.StatusCreated {
		t.Fatalf("create user: %d %s", code, body)
	}
	var ada struct{ ID string }
	if err := json.Unmarshal([]byte(body), &ada); err != nil {
		t.Fatal(err)
	}
	adaID := uuid.MustParse(ada.ID)
	if got := role(adaID, acme); got != "member" {
		t.Fatalf("provisioned user's graph role = %q, want member", got)
	}
	if code, body := scimUserByID(t, svc, tok.Token, http.MethodDelete, ada.ID); code != http.StatusNoContent {
		t.Fatalf("delete user: %d %s", code, body)
	}
	if got := role(adaID, acme); got != "" {
		t.Fatalf("deleted user's graph role = %q, want none", got)
	}

	// RunJobs runs the reconciler at startup and until cancelled.
	runs := res.Reconciler.Stats().Runs
	jobsCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- svc.RunJobs(jobsCtx) }()
	deadline := time.Now().Add(10 * time.Second)
	for res.Reconciler.Stats().Runs == runs {
		if time.Now().After(deadline) {
			t.Fatal("RunJobs did not reconcile at startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()
	if err := <-done; err != nil {
		t.Fatalf("RunJobs: %v", err)
	}
	if st := res.Reconciler.Stats(); st.LastError != nil {
		t.Errorf("reconciler failed: %v", st.LastError)
	}
}

// scimUserByID calls the SCIM endpoint of one user with a tenant token.
func scimUserByID(t *testing.T, svc *systemauthsvc.Service, token, method, id string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(method, mpIssuer+systemauthsvc.SCIMPath+"/Users/"+id, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	svc.Handler().ServeHTTP(w, r)
	return w.Code, w.Body.String()
}
