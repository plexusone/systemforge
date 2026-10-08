package rls_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/rls"
	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

// SET LOCAL outside a transaction does nothing, so the helper must refuse
// executors that are not transactions rather than leave queries unscoped.
func TestHelper_RefusesNonTransactionExecutors(t *testing.T) {
	h := rls.NewHelper(nil)
	ctx := context.Background()

	for name, exec := range map[string]rls.Executor{"DB": new(sql.DB), "Conn": new(sql.Conn)} {
		if err := h.SetTenant(ctx, exec, uuid.NewString()); !errors.Is(err, rls.ErrNotInTransaction) {
			t.Errorf("SetTenant on *sql.%s: error = %v, want ErrNotInTransaction", name, err)
		}
		if err := h.SetUser(ctx, exec, uuid.NewString()); !errors.Is(err, rls.ErrNotInTransaction) {
			t.Errorf("SetUser on *sql.%s: error = %v, want ErrNotInTransaction", name, err)
		}
	}
}

func TestContextInjector_FailsLoudlyOutsideTransaction(t *testing.T) {
	ci := rls.NewContextInjector(nil)
	ctx := rls.ContextWithTenant(context.Background(), uuid.New())
	if err := ci.InjectContext(ctx, new(sql.Conn)); !errors.Is(err, rls.ErrNotInTransaction) {
		t.Errorf("InjectContext: error = %v, want ErrNotInTransaction", err)
	}
}

// The middleware only carries the caller's identity; it must not touch the
// database, which it would do through a pooled connection where SET LOCAL has
// no effect.
func TestMiddleware_SetRLSContextCarriesIdentityWithoutDatabase(t *testing.T) {
	mw := rls.NewMiddleware(nil, nil)
	org, principal := uuid.New(), uuid.New()

	var gotTenant, gotUser uuid.UUID
	h := mw.SetRLSContext()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = rls.TenantIDFromContext(r.Context())
		gotUser = rls.UserIDFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := &jwt.Claims{PrincipalID: principal, OrganizationID: &org}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if gotTenant != org || gotUser != principal {
		t.Errorf("context tenant=%s user=%s, want %s and %s", gotTenant, gotUser, org, principal)
	}
}
