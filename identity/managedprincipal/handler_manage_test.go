package managedprincipal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// TestManagementEndpoints drives the managing routes over HTTP, checking
// that each reaches the service operation and its authorizer checks.
func TestManagementEndpoints(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	h := NewHandler(svc)
	guardian := addVerifiedHuman(t, db, "guardian@example.com")
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	adult := addVerifiedHuman(t, db, "adult@example.com")
	outsider := addVerifiedHuman(t, db, "outsider@example.com")

	do := func(actor uuid.UUID, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var rdr *bytes.Reader
		if body != nil {
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rdr)
		if actor != uuid.Nil {
			req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), &requestprincipal.RequestPrincipal{PrincipalID: actor.String()}))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	expect := func(w *httptest.ResponseRecorder, want int) {
		t.Helper()
		if w.Code != want {
			t.Fatalf("status %d, want %d: %s", w.Code, want, w.Body)
		}
	}
	decode := func(w *httptest.ResponseRecorder, v any) {
		t.Helper()
		if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
			t.Fatalf("decode %q: %v", w.Body, err)
		}
	}

	// Create.
	expect(do(uuid.Nil, http.MethodPost, "/", nil), http.StatusUnauthorized)
	body := CreateRequest{ClientID: client, DisplayName: "Robin",
		Managers: []ManagerView{{PrincipalID: guardian, Role: RoleGuardian}, {PrincipalID: teacher, Role: RoleEducator}}}
	expect(do(outsider, http.MethodPost, "/", body), http.StatusForbidden)
	expect(do(guardian, http.MethodPost, "/", CreateRequest{ClientID: client, Managers: body.Managers}), http.StatusBadRequest)
	w := do(guardian, http.MethodPost, "/", body)
	expect(w, http.StatusCreated)
	var created struct {
		ID uuid.UUID `json:"id"`
	}
	decode(w, &created)
	base := "/" + created.ID.String()

	// Managers.
	w = do(teacher, http.MethodGet, base+"/managers", nil)
	expect(w, http.StatusOK)
	var listed struct {
		Managers []ManagerView `json:"managers"`
	}
	decode(w, &listed)
	if len(listed.Managers) != 2 {
		t.Errorf("managers = %+v", listed.Managers)
	}
	expect(do(outsider, http.MethodGet, base+"/managers", nil), http.StatusForbidden)
	expect(do(teacher, http.MethodPost, base+"/managers", ManagerView{PrincipalID: outsider, Role: RoleEducator}), http.StatusForbidden)
	expect(do(guardian, http.MethodPost, base+"/managers", ManagerView{PrincipalID: outsider, Role: RoleEducator}), http.StatusNoContent)
	expect(do(teacher, http.MethodDelete, base+"/managers/"+outsider.String()+"/"+RoleEducator, nil), http.StatusForbidden)
	expect(do(guardian, http.MethodDelete, base+"/managers/"+outsider.String()+"/"+RoleEducator, nil), http.StatusNoContent)
	expect(do(guardian, http.MethodDelete, base+"/managers/"+outsider.String()+"/"+RoleEducator, nil), http.StatusNotFound)
	expect(do(guardian, http.MethodDelete, base+"/managers/"+guardian.String()+"/"+RoleGuardian, nil), http.StatusNoContent)
	expect(do(teacher, http.MethodDelete, base+"/managers/"+teacher.String()+"/"+RoleEducator, nil), http.StatusForbidden)

	// Claims: the educator issues one and a new guardian redeems it.
	w = do(teacher, http.MethodPost, base+"/claims", nil)
	expect(w, http.StatusCreated)
	var claim struct {
		Code string `json:"code"`
	}
	decode(w, &claim)
	expect(do(adult, http.MethodPost, "/claims/redeem", map[string]string{"code": "SFMCNOPE"}), http.StatusBadRequest)
	w = do(adult, http.MethodPost, "/claims/redeem", map[string]string{"code": claim.Code})
	expect(w, http.StatusOK)
	var redeemed struct {
		ID uuid.UUID `json:"principal_id"`
	}
	decode(w, &redeemed)
	if redeemed.ID != created.ID {
		t.Errorf("redeemed %v, want %v", redeemed.ID, created.ID)
	}

	// Delete: an educator cannot; the new guardian can.
	expect(do(teacher, http.MethodDelete, base, nil), http.StatusForbidden)
	expect(do(adult, http.MethodDelete, base, nil), http.StatusNoContent)
	// The principal is gone, which is answered as for any principal that
	// is not the caller's.
	expect(do(adult, http.MethodDelete, base, nil), http.StatusForbidden)
}

// TestInviteEndpoints drives the consent flow over HTTP and the release
// route that ends it.
func TestInviteEndpoints(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	h := NewHandler(svc)
	family := addVerifiedHuman(t, db, "family@example.com")
	adult := addVerifiedHuman(t, db, "adult@example.com")
	stranger := addVerifiedHuman(t, db, "stranger@example.com")

	do := func(actor uuid.UUID, method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req = req.WithContext(requestprincipal.WithPrincipal(req.Context(), &requestprincipal.RequestPrincipal{PrincipalID: actor.String()}))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}

	w := do(family, http.MethodPost, "/manager-invites", map[string]string{"client_id": client, "email": "adult@example.com", "role": RoleGuardian})
	if w.Code != http.StatusCreated {
		t.Fatalf("invite: %d %s", w.Code, w.Body)
	}
	var inv struct {
		ID    uuid.UUID `json:"id"`
		Token string    `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &inv); err != nil {
		t.Fatal(err)
	}
	if w := do(stranger, http.MethodPost, "/manager-invites/accept", map[string]string{"token": inv.Token}); w.Code != http.StatusBadRequest {
		t.Errorf("accept by a stranger: %d", w.Code)
	}
	if w := do(adult, http.MethodPost, "/manager-invites/accept", map[string]string{"token": inv.Token}); w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body)
	}
	if w := do(adult, http.MethodPost, "/manager-invites/accept", map[string]string{"token": inv.Token}); w.Code != http.StatusBadRequest {
		t.Errorf("second accept: %d", w.Code)
	}
	if w := do(family, http.MethodDelete, "/manager-invites/"+inv.ID.String(), struct{}{}); w.Code != http.StatusNotFound {
		t.Errorf("revoke an accepted invite: %d", w.Code)
	}
	if w := do(adult, http.MethodPost, "/"+adult.String()+"/release", struct{}{}); w.Code != http.StatusForbidden {
		t.Errorf("release by the released principal: %d, want 403", w.Code)
	}
	if w := do(family, http.MethodPost, "/"+adult.String()+"/release", struct{}{}); w.Code != http.StatusNoContent {
		t.Errorf("release by the guardian: %d %s", w.Code, w.Body)
	}
	// Decline.
	decl := do(family, http.MethodPost, "/manager-invites", map[string]string{"client_id": client, "email": "adult@example.com", "role": RoleEducator})
	if decl.Code != http.StatusCreated {
		t.Fatalf("second invite: %d %s", decl.Code, decl.Body)
	}
	var second struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(decl.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	if w := do(stranger, http.MethodPost, "/manager-invites/decline", map[string]string{"token": second.Token}); w.Code != http.StatusBadRequest {
		t.Errorf("decline by a stranger: %d, want 400", w.Code)
	}
	if w := do(adult, http.MethodPost, "/manager-invites/decline", map[string]string{"token": second.Token}); w.Code != http.StatusNoContent {
		t.Errorf("decline: %d %s", w.Code, w.Body)
	}
	if w := do(adult, http.MethodPost, "/manager-invites/decline", map[string]string{"token": second.Token}); w.Code != http.StatusBadRequest {
		t.Errorf("second decline: %d, want 400", w.Code)
	}
	// Unknown fields are refused.
	if w := do(family, http.MethodPost, "/manager-invites", map[string]string{"client_id": client, "email": "x@example.com", "role": RoleGuardian, "extra": "1"}); w.Code != http.StatusBadRequest {
		t.Errorf("unknown field: %d", w.Code)
	}
}
