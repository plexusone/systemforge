package scim

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// usersPath is the bulk operation path of the Users endpoint.
const usersPath = "/Users"

func bulkUser(i int, password bool) map[string]any {
	data := map[string]any{"userName": fmt.Sprintf("u%d@example.com", i)}
	if password {
		data["password"] = "Secret-1"
	}
	return data
}

// A bulk request may set only a bounded number of passwords, since each
// one costs a password hash.
func TestBulkPasswordOperationsAreBounded(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()
	cfg.BulkMaxPasswordOperations = 2
	p, err := NewProvider(cfg, newMockStore(), WithAuthorizationHook(AllowAllAuthorizationHook{}))
	if err != nil {
		t.Fatal(err)
	}
	svc := p.Service()

	ops := []BulkOperation{
		{Method: "POST", Path: usersPath, Data: bulkUser(1, true)},
		{Method: "POST", Path: usersPath, Data: bulkUser(2, false)},
		{Method: "PATCH", Path: usersPath + "/user-1", Data: map[string]any{"Operations": []any{
			map[string]any{"op": "replace", "path": "PASSWORD", "value": "Secret-2"},
		}}},
	}
	if _, err := svc.ProcessBulk(ctx, &BulkRequest{Operations: ops}); err != nil {
		t.Fatalf("two password operations: %v", err)
	}
	ops = append(ops, BulkOperation{Method: "PUT", Path: usersPath + "/user-2", Data: bulkUser(3, true)})
	_, err = svc.ProcessBulk(ctx, &BulkRequest{Operations: ops})
	if e := ToSCIMError(err); err == nil || e.Status != http.StatusBadRequest || e.ScimType != ErrorTypeTooMany {
		t.Errorf("three password operations: %v", err)
	}

	cfg.BulkMaxPasswordOperations = -1
	if _, err := svc.ProcessBulk(ctx, &BulkRequest{Operations: ops[:1]}); err == nil {
		t.Error("negative limit allowed a password")
	}
	if got := countBulkPasswords([]BulkOperation{{Data: map[string]any{"Operations": []any{
		map[string]any{"op": "replace", "value": map[string]any{"password": "x"}},
	}}}}); got != 1 {
		t.Errorf("password in a PATCH value counted %d", got)
	}
}

// The advertised Bulk maxPayloadSize is enforced as the body limit.
func TestBulkPayloadSizeIsEnforced(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BulkMaxPayloadSize = 512
	p, err := NewProvider(cfg, newMockStore(), WithAuthorizationHook(AllowAllAuthorizationHook{}))
	if err != nil {
		t.Fatal(err)
	}
	api, err := NewAPI(p)
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, cfg.BaseURL+"/Bulk", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/scim+json")
		rr := httptest.NewRecorder()
		api.ServeHTTP(rr, req)
		return rr.Code
	}
	small := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[]}`
	if code := post(small); code != http.StatusOK {
		t.Fatalf("small bulk request: %d", code)
	}
	big := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],"Operations":[],"pad":"` + strings.Repeat("x", 1024) + `"}`
	if code := post(big); code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized bulk request: %d, want 413", code)
	}
}

// batchStore records how list pages load memberships.
type batchStore struct {
	*mockStore
	perResource, batched int
}

func (s *batchStore) GetGroupsForUser(ctx context.Context, id string) ([]GroupRef, error) {
	s.perResource++
	return s.mockStore.GetGroupsForUser(ctx, id)
}

func (s *batchStore) GetMembersForGroup(ctx context.Context, id string) ([]MemberRef, error) {
	s.perResource++
	return s.mockStore.GetMembersForGroup(ctx, id)
}

func (s *batchStore) GetGroupsForUsers(_ context.Context, ids []string) (map[string][]GroupRef, error) {
	s.batched++
	out := map[string][]GroupRef{}
	for _, id := range ids {
		out[id] = []GroupRef{{Value: "g-" + id}}
	}
	return out, nil
}

func (s *batchStore) GetMembersForGroups(_ context.Context, ids []string) (map[string][]MemberRef, error) {
	s.batched++
	out := map[string][]MemberRef{}
	for _, id := range ids {
		out[id] = []MemberRef{{Value: "m-" + id}}
	}
	return out, nil
}

// List pages load memberships in one call when the store supports it.
func TestListPagesLoadMembershipsInOneCall(t *testing.T) {
	ctx := context.Background()
	st := &batchStore{mockStore: newMockStore()}
	p, err := NewProvider(DefaultConfig(), st, WithAuthorizationHook(AllowAllAuthorizationHook{}))
	if err != nil {
		t.Fatal(err)
	}
	svc := p.Service()
	for i := range 3 {
		if _, err := svc.CreateUser(ctx, &User{UserName: fmt.Sprintf("u%d@example.com", i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := st.CreateGroup(ctx, &Group{DisplayName: fmt.Sprintf("G%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	st.perResource, st.batched = 0, 0

	users, err := svc.ListUsers(ctx, ListOptions{StartIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	groups, err := svc.ListGroups(ctx, ListOptions{StartIndex: 1})
	if err != nil {
		t.Fatal(err)
	}
	if st.perResource != 0 || st.batched != 2 {
		t.Errorf("per-resource calls %d, batched calls %d; want 0 and 2", st.perResource, st.batched)
	}
	for _, r := range users.Resources {
		u := r.(*User)
		if len(u.Groups) != 1 || u.Groups[0].Value != "g-"+u.ID {
			t.Errorf("user %s groups = %+v", u.ID, u.Groups)
		}
	}
	for _, r := range groups.Resources {
		g := r.(*Group)
		if len(g.Members) != 1 || g.Members[0].Value != "m-"+g.ID {
			t.Errorf("group %s members = %+v", g.ID, g.Members)
		}
	}
}
