package authz_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/session/jwt"
	"github.com/plexusone/systemforge/session/middleware"
)

// resourceFixture is a member of orgA with document.read, and one document
// owned by each organization.
type resourceFixture struct {
	orgA, orgB     uuid.UUID
	member         uuid.UUID
	docA, docB     uuid.UUID
	lookupFailures map[uuid.UUID]error
}

func newResourceFixture() *resourceFixture {
	return &resourceFixture{
		orgA: uuid.New(), orgB: uuid.New(), member: uuid.New(),
		docA: uuid.New(), docB: uuid.New(),
		lookupFailures: map[uuid.UUID]error{},
	}
}

func (f *resourceFixture) provider() *rbac.Provider {
	return rbac.New(
		rbac.WithPermissions(authz.RolePermissions{"member": {"document.read"}}),
		rbac.WithRoleGetter(func(_ context.Context, principalID, orgID uuid.UUID) (string, error) {
			if principalID == f.member && orgID == f.orgA {
				return "member", nil
			}
			return "", nil
		}),
	)
}

func (f *resourceFixture) lookup(_ context.Context, id uuid.UUID) (uuid.UUID, error) {
	if err, ok := f.lookupFailures[id]; ok {
		return uuid.Nil, err
	}
	switch id {
	case f.docA:
		return f.orgA, nil
	case f.docB:
		return f.orgB, nil
	}
	return uuid.Nil, authz.ErrResourceNotFound
}

// serve requests document id as the member, whose token names orgA.
func (f *resourceFixture) serve(t *testing.T, extractor authz.ResourceExtractor, id string) int {
	t.Helper()
	mw := authz.NewMiddleware(f.provider()).RequireResourceAction(extractor, authz.ActionRead)
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/documents/"+id, nil)
	req.SetPathValue("id", id)
	claims := &jwt.Claims{PrincipalID: f.member, OrganizationID: &f.orgA}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func pathValue(r *http.Request, key string) string { return r.PathValue(key) }

// A member of org A must not pass a resource check for a resource of org B
// by naming its ID; the check uses the resource's owning organization.
func TestRequireResourceActionUsesOwningOrganization(t *testing.T) {
	f := newResourceFixture()
	extractor := authz.WithResourceLookup("document", "id", pathValue, f.lookup)

	if got := f.serve(t, extractor, f.docA.String()); got != http.StatusOK {
		t.Errorf("own organization's document: status %d, want 200", got)
	}
	if got := f.serve(t, extractor, f.docB.String()); got != http.StatusForbidden {
		t.Errorf("other organization's document: status %d, want 403", got)
	}
	if got := f.serve(t, extractor, uuid.NewString()); got != http.StatusForbidden {
		t.Errorf("missing document: status %d, want 403", got)
	}
	if got := f.serve(t, extractor, "not-a-uuid"); got != http.StatusBadRequest {
		t.Errorf("malformed ID: status %d, want 400", got)
	}
	f.lookupFailures[f.docA] = errors.New("database down")
	if got := f.serve(t, extractor, f.docA.String()); got != http.StatusInternalServerError {
		t.Errorf("lookup failure: status %d, want 500", got)
	}
}

// Without a lookup the token's organization is no longer assumed, so an
// organization role alone does not grant access to an arbitrary resource ID.
func TestRequireResourceActionDoesNotAssumeTokenOrganization(t *testing.T) {
	f := newResourceFixture()
	extractor := authz.WithResourceID("document", "id", pathValue)
	if got := f.serve(t, extractor, f.docB.String()); got != http.StatusForbidden {
		t.Errorf("resource ID without an organization: status %d, want 403", got)
	}
}
