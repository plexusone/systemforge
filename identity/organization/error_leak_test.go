package organization_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/organization"
)

// errInternal stands in for a database error whose text must never reach
// a client.
var errInternal = errors.New(`pq: relation "secret_table" violates constraint "secret_idx"`)

// failingMembers is a Service whose ListMembers fails with errInternal.
type failingMembers struct {
	organization.Service
}

func (failingMembers) ListMembers(context.Context, uuid.UUID, ...organization.ListOption) ([]*organization.Membership, error) {
	return nil, errInternal
}

// TestInternalErrorsDoNotLeak expects a failing store or entitlement
// source to answer 500 with a generic message, not the error's text.
func TestInternalErrorsDoNotLeak(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	svc := organization.NewService(db)
	owner := newHuman(t, db, "owner@example.com")
	if _, err := svc.Create(ctx, organization.CreateOrganizationInput{Name: "Acme", Slug: "acme", OrgType: organization.OrgTypeTeam, OwnerPrincipalID: &owner}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	cfg := organization.DefaultAPIConfig()
	cfg.Authorizer = memberAuthorizer(svc)
	cfg.Entitlements = func(context.Context, uuid.UUID) ([]organization.Entitlement, error) {
		return nil, errInternal
	}
	api := &orgAPI{t: t, db: db, svc: svc, h: organization.NewAPI(failingMembers{svc}, cfg)}

	for _, path := range []string{"/organizations/acme", "/organizations/acme/members"} {
		code, body := api.do(http.MethodGet, path, owner, nil)
		if code != http.StatusInternalServerError {
			t.Errorf("GET %s = %d %s, want 500", path, code, body)
		}
		if strings.Contains(string(body), "secret") {
			t.Errorf("GET %s leaks the internal error: %s", path, body)
		}
	}

	// A known service error keeps its fixed, actionable message.
	code, body := api.do(http.MethodPost, "/organizations", owner, map[string]any{"name": "Dup", "slug": "acme"})
	if code != http.StatusBadRequest || !strings.Contains(string(body), organization.ErrSlugTaken.Error()) {
		t.Errorf("duplicate slug = %d %s, want 400 %q", code, body, organization.ErrSlugTaken)
	}
}
