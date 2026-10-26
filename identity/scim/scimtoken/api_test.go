package scimtoken_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
)

type callerKey struct{}

func TestAPI(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	api, err := scimtoken.NewAPI(s, scimtoken.APIConfig{
		Organizations: organization.NewService(f.client),
		Caller: func(ctx context.Context) (uuid.UUID, error) {
			id, ok := ctx.Value(callerKey{}).(uuid.UUID)
			if !ok {
				return uuid.Nil, requestprincipal.ErrNoPrincipal
			}
			return id, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	do := func(caller uuid.UUID, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if caller != uuid.Nil {
			req = req.WithContext(context.WithValue(req.Context(), callerKey{}, caller))
		}
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)
		return rr
	}
	const base = "/api/v1/organizations/acme/scim-tokens"

	if rr := do(uuid.Nil, http.MethodGet, base, ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous list: %d", rr.Code)
	}
	if rr := do(f.memberA, http.MethodPost, base, `{}`); rr.Code != http.StatusForbidden {
		t.Fatalf("member issue: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(f.ownerA, http.MethodGet, "/api/v1/organizations/nope/scim-tokens", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown organization: %d", rr.Code)
	}

	rr := do(f.ownerA, http.MethodPost, base, `{"description":"idp"}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("issue: %d %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("issue response is cacheable")
	}
	var first scimtoken.Issued
	if err := json.Unmarshal(rr.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.Token, scimtoken.Prefix) || first.Metadata.Description != "idp" {
		t.Fatalf("issued: prefix %q description %q", first.Metadata.Prefix, first.Metadata.Description)
	}
	if rr := do(f.ownerA, http.MethodPost, base, `{}`); rr.Code != http.StatusConflict {
		t.Fatalf("second issue: %d", rr.Code)
	}
	rr = do(f.adminA, http.MethodPost, base+"/rotate", `{}`)
	if rr.Code != http.StatusCreated {
		t.Fatalf("rotate: %d %s", rr.Code, rr.Body.String())
	}
	var second scimtoken.Issued
	if err := json.Unmarshal(rr.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}

	rr = do(f.ownerA, http.MethodGet, base, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	if strings.Contains(rr.Body.String(), first.Token) || strings.Contains(rr.Body.String(), second.Token) {
		t.Fatal("list response carries a token")
	}
	var list struct {
		Tokens []scimtoken.Token `json:"tokens"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Tokens) != 2 || list.Tokens[0].Status != scimtoken.StatusCurrent || list.Tokens[1].Status != scimtoken.StatusPrevious {
		t.Fatalf("list: %+v", list.Tokens)
	}

	if rr := do(f.ownerA, http.MethodDelete, base+"/"+second.Metadata.ID.String(), ""); rr.Code != http.StatusNoContent {
		t.Fatalf("revoke: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(f.ownerA, http.MethodDelete, base+"/"+uuid.NewString(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown token: %d", rr.Code)
	}
	if _, err := s.Authenticate(context.Background(), first.Token); err != nil {
		t.Fatalf("previous token after rollback: %v", err)
	}
}
