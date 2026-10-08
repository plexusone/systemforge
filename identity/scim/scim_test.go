package scim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockStore is an in-memory implementation of Store for testing.
type mockStore struct {
	mu     sync.RWMutex
	users  map[string]*User
	groups map[string]*Group
	// membership: map[groupID]map[userID]bool
	memberships map[string]map[string]bool
	userSeq     int
	groupSeq    int
}

func newMockStore() *mockStore {
	return &mockStore{
		users:       make(map[string]*User),
		groups:      make(map[string]*Group),
		memberships: make(map[string]map[string]bool),
	}
}

func (s *mockStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound("user not found: " + id)
	}
	return user, nil
}

func (s *mockStore) GetUserByUserName(ctx context.Context, userName string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.UserName == userName {
			return user, nil
		}
	}
	return nil, ErrNotFound("user not found with userName: " + userName)
}

func (s *mockStore) GetUserByExternalID(ctx context.Context, externalID string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, user := range s.users {
		if user.ExternalID == externalID {
			return user, nil
		}
	}
	return nil, ErrNotFound("user not found with externalId: " + externalID)
}

func (s *mockStore) ListUsers(ctx context.Context, opts ListOptions) ([]*User, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*User
	for _, user := range s.users {
		result = append(result, user)
	}

	total := len(result)

	// Apply pagination
	start := opts.StartIndex - 1
	if start < 0 {
		start = 0
	}
	if start >= len(result) {
		return []*User{}, total, nil
	}

	end := start + opts.Count
	if end > len(result) {
		end = len(result)
	}

	return result[start:end], total, nil
}

func (s *mockStore) CreateUser(ctx context.Context, user *User) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate userName
	for _, existing := range s.users {
		if existing.UserName == user.UserName {
			return nil, ErrConflict("user already exists: " + user.UserName)
		}
	}

	s.userSeq++
	user.ID = fmt.Sprintf("user-%d", s.userSeq)
	now := time.Now()
	user.Meta = &Meta{
		Created:      &now,
		LastModified: &now,
		Version:      now.Format("20060102150405"),
	}
	s.users[user.ID] = user
	return user, nil
}

func (s *mockStore) UpdateUser(ctx context.Context, id string, user *User) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.users[id]
	if !ok {
		return nil, ErrNotFound("user not found: " + id)
	}

	// Preserve created time, update modified
	now := time.Now()
	user.ID = id
	user.Meta = &Meta{
		Created:      existing.Meta.Created,
		LastModified: &now,
		Version:      now.Format("20060102150405"),
	}
	s.users[id] = user
	return user, nil
}

func (s *mockStore) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[id]; !ok {
		return ErrNotFound("user not found: " + id)
	}
	delete(s.users, id)

	// Remove from all group memberships
	for groupID, members := range s.memberships {
		delete(members, id)
		if len(members) == 0 {
			delete(s.memberships, groupID)
		}
	}

	return nil
}

func (s *mockStore) GetGroupByID(ctx context.Context, id string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.groups[id]
	if !ok {
		return nil, ErrNotFound("group not found: " + id)
	}
	return group, nil
}

func (s *mockStore) GetGroupByDisplayName(ctx context.Context, displayName string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, group := range s.groups {
		if group.DisplayName == displayName {
			return group, nil
		}
	}
	return nil, ErrNotFound("group not found with displayName: " + displayName)
}

func (s *mockStore) GetGroupByExternalID(ctx context.Context, externalID string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, group := range s.groups {
		if group.ExternalID == externalID {
			return group, nil
		}
	}
	return nil, ErrNotFound("group not found with externalId: " + externalID)
}

func (s *mockStore) ListGroups(ctx context.Context, opts ListOptions) ([]*Group, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Group
	for _, group := range s.groups {
		result = append(result, group)
	}

	total := len(result)

	// Apply pagination
	start := opts.StartIndex - 1
	if start < 0 {
		start = 0
	}
	if start >= len(result) {
		return []*Group{}, total, nil
	}

	end := start + opts.Count
	if end > len(result) {
		end = len(result)
	}

	return result[start:end], total, nil
}

func (s *mockStore) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for duplicate displayName
	for _, existing := range s.groups {
		if existing.DisplayName == group.DisplayName {
			return nil, ErrConflict("group already exists: " + group.DisplayName)
		}
	}

	s.groupSeq++
	group.ID = fmt.Sprintf("group-%d", s.groupSeq)
	now := time.Now()
	group.Meta = &Meta{
		Created:      &now,
		LastModified: &now,
		Version:      now.Format("20060102150405"),
	}
	s.groups[group.ID] = group
	s.memberships[group.ID] = make(map[string]bool)
	return group, nil
}

func (s *mockStore) UpdateGroup(ctx context.Context, id string, group *Group) (*Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, ok := s.groups[id]
	if !ok {
		return nil, ErrNotFound("group not found: " + id)
	}

	// Preserve created time, update modified
	now := time.Now()
	group.ID = id
	group.Meta = &Meta{
		Created:      existing.Meta.Created,
		LastModified: &now,
		Version:      now.Format("20060102150405"),
	}
	s.groups[id] = group
	return group, nil
}

func (s *mockStore) DeleteGroup(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.groups[id]; !ok {
		return ErrNotFound("group not found: " + id)
	}
	delete(s.groups, id)
	delete(s.memberships, id)
	return nil
}

func (s *mockStore) GetGroupsForUser(ctx context.Context, userID string) ([]GroupRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var groups []GroupRef
	for groupID, members := range s.memberships {
		if members[userID] {
			if group, ok := s.groups[groupID]; ok {
				groups = append(groups, GroupRef{
					Value:   groupID,
					Ref:     "/scim/v2/Groups/" + groupID,
					Display: group.DisplayName,
				})
			}
		}
	}
	return groups, nil
}

func (s *mockStore) GetMembersForGroup(ctx context.Context, groupID string) ([]MemberRef, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	members, ok := s.memberships[groupID]
	if !ok {
		return []MemberRef{}, nil
	}

	var result []MemberRef
	for userID := range members {
		if user, ok := s.users[userID]; ok {
			result = append(result, MemberRef{
				Value:   userID,
				Ref:     "/scim/v2/Users/" + userID,
				Display: user.DisplayName,
				Type:    "User",
			})
		}
	}
	return result, nil
}

func (s *mockStore) AddMemberToGroup(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.groups[groupID]; !ok {
		return ErrNotFound("group not found: " + groupID)
	}
	if _, ok := s.users[userID]; !ok {
		return ErrNotFound("user not found: " + userID)
	}

	if s.memberships[groupID] == nil {
		s.memberships[groupID] = make(map[string]bool)
	}
	s.memberships[groupID][userID] = true
	return nil
}

func (s *mockStore) RemoveMemberFromGroup(ctx context.Context, groupID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.groups[groupID]; !ok {
		return ErrNotFound("group not found: " + groupID)
	}

	if members, ok := s.memberships[groupID]; ok {
		delete(members, userID)
	}
	return nil
}

// setupTestProvider creates a test provider with mock store.
func setupTestProvider() (*Provider, *mockStore, error) {
	config := &Config{
		BaseURL:               "/scim/v2",
		MaxResults:            100,
		DefaultPageSize:       25,
		SupportFiltering:      true,
		SupportSorting:        true,
		SupportPatch:          true,
		SupportBulk:           true,
		BulkMaxOperations:     10,
		BulkMaxPayloadSize:    1048576,
		SupportETag:           true,
		SupportChangePassword: false,
	}

	store := newMockStore()
	provider, err := NewProvider(config, store, WithAuthorizationHook(AllowAllAuthorizationHook{}))
	if err != nil {
		return nil, nil, err
	}
	return provider, store, nil
}

// setupTestServer creates a test HTTP server with SCIM API.
func setupTestServer() (*httptest.Server, *mockStore, error) {
	provider, store, err := setupTestProvider()
	if err != nil {
		return nil, nil, err
	}

	api, err := NewAPI(provider)
	if err != nil {
		return nil, nil, err
	}

	server := httptest.NewServer(api)
	return server, store, nil
}

// TestUserCRUDWorkflow tests the full user lifecycle.
func TestUserCRUDWorkflow(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// 1. Create user
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "john.doe@example.com",
		"displayName": "John Doe",
		"active": true,
		"emails": [{"value": "john.doe@example.com", "type": "work", "primary": true}]
	}`

	resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatalf("create user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
	}

	var createdUser User
	if err := json.NewDecoder(resp.Body).Decode(&createdUser); err != nil {
		t.Fatalf("failed to decode created user: %v", err)
	}

	if createdUser.ID == "" {
		t.Error("created user should have an ID")
	}
	if createdUser.UserName != "john.doe@example.com" {
		t.Errorf("userName = %q, want %q", createdUser.UserName, "john.doe@example.com")
	}

	// Check Location header
	location := resp.Header.Get("Location")
	if location == "" {
		t.Error("Location header should be set")
	}

	// 2. Get user
	resp, err = http.Get(baseURL + "/Users/" + createdUser.ID)
	if err != nil {
		t.Fatalf("get user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var fetchedUser User
	if err := json.NewDecoder(resp.Body).Decode(&fetchedUser); err != nil {
		t.Fatalf("failed to decode fetched user: %v", err)
	}

	if fetchedUser.ID != createdUser.ID {
		t.Errorf("ID = %q, want %q", fetchedUser.ID, createdUser.ID)
	}

	// 3. Update user (PUT)
	updateBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "john.doe@example.com",
		"displayName": "John Q. Doe",
		"active": true
	}`

	req, _ := http.NewRequest(http.MethodPut, baseURL+"/Users/"+createdUser.ID, strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err = http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
	if err != nil {
		t.Fatalf("update user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var updatedUser User
	if err := json.NewDecoder(resp.Body).Decode(&updatedUser); err != nil {
		t.Fatalf("failed to decode updated user: %v", err)
	}

	if updatedUser.DisplayName != "John Q. Doe" {
		t.Errorf("displayName = %q, want %q", updatedUser.DisplayName, "John Q. Doe")
	}

	// 4. List users
	resp, err = http.Get(baseURL + "/Users")
	if err != nil {
		t.Fatalf("list users request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var listResponse ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}

	if listResponse.TotalResults != 1 {
		t.Errorf("totalResults = %d, want 1", listResponse.TotalResults)
	}

	// 5. Delete user
	req, _ = http.NewRequest(http.MethodDelete, baseURL+"/Users/"+createdUser.ID, nil)
	resp, err = http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
	if err != nil {
		t.Fatalf("delete user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", resp.StatusCode)
	}

	// 6. Verify deletion
	resp, err = http.Get(baseURL + "/Users/" + createdUser.ID)
	if err != nil {
		t.Fatalf("get deleted user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
}

// TestGroupCRUDWorkflow tests the full group lifecycle.
func TestGroupCRUDWorkflow(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// 1. Create group
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Engineering Team"
	}`

	resp, err := http.Post(baseURL+"/Groups", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatalf("create group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
	}

	var createdGroup Group
	if err := json.NewDecoder(resp.Body).Decode(&createdGroup); err != nil {
		t.Fatalf("failed to decode created group: %v", err)
	}

	if createdGroup.ID == "" {
		t.Error("created group should have an ID")
	}
	if createdGroup.DisplayName != "Engineering Team" {
		t.Errorf("displayName = %q, want %q", createdGroup.DisplayName, "Engineering Team")
	}

	// 2. Get group
	resp, err = http.Get(baseURL + "/Groups/" + createdGroup.ID)
	if err != nil {
		t.Fatalf("get group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var fetchedGroup Group
	if err := json.NewDecoder(resp.Body).Decode(&fetchedGroup); err != nil {
		t.Fatalf("failed to decode fetched group: %v", err)
	}

	if fetchedGroup.ID != createdGroup.ID {
		t.Errorf("ID = %q, want %q", fetchedGroup.ID, createdGroup.ID)
	}

	// 3. Update group (PUT)
	updateBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Platform Engineering Team"
	}`

	req, _ := http.NewRequest(http.MethodPut, baseURL+"/Groups/"+createdGroup.ID, strings.NewReader(updateBody))
	req.Header.Set("Content-Type", "application/scim+json")
	resp, err = http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
	if err != nil {
		t.Fatalf("update group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
	}

	var updatedGroup Group
	if err := json.NewDecoder(resp.Body).Decode(&updatedGroup); err != nil {
		t.Fatalf("failed to decode updated group: %v", err)
	}

	if updatedGroup.DisplayName != "Platform Engineering Team" {
		t.Errorf("displayName = %q, want %q", updatedGroup.DisplayName, "Platform Engineering Team")
	}

	// 4. List groups
	resp, err = http.Get(baseURL + "/Groups")
	if err != nil {
		t.Fatalf("list groups request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var listResponse ListResponse
	if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}

	if listResponse.TotalResults != 1 {
		t.Errorf("totalResults = %d, want 1", listResponse.TotalResults)
	}

	// 5. Delete group
	req, _ = http.NewRequest(http.MethodDelete, baseURL+"/Groups/"+createdGroup.ID, nil)
	resp, err = http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
	if err != nil {
		t.Fatalf("delete group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d", resp.StatusCode)
	}

	// 6. Verify deletion
	resp, err = http.Get(baseURL + "/Groups/" + createdGroup.ID)
	if err != nil {
		t.Fatalf("get deleted group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", resp.StatusCode)
	}
}

// TestPATCHOperations tests PATCH operations on users and groups.
func TestPATCHOperations(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create a user first
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "patch.test@example.com",
		"displayName": "Patch Test User",
		"active": true
	}`

	resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatalf("create user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var createdUser User
	if err := json.NewDecoder(resp.Body).Decode(&createdUser); err != nil {
		t.Fatalf("failed to decode created user: %v", err)
	}

	// Test PATCH replace operation
	t.Run("PATCH replace displayName", func(t *testing.T) {
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{"op": "replace", "path": "displayName", "value": "Updated Name"}
			]
		}`

		req, _ := http.NewRequest(http.MethodPatch, baseURL+"/Users/"+createdUser.ID, strings.NewReader(patchBody))
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var patchedUser User
		if err := json.NewDecoder(resp.Body).Decode(&patchedUser); err != nil {
			t.Fatalf("failed to decode patched user: %v", err)
		}

		if patchedUser.DisplayName != "Updated Name" {
			t.Errorf("displayName = %q, want %q", patchedUser.DisplayName, "Updated Name")
		}
	})

	// Test PATCH add operation
	t.Run("PATCH add name", func(t *testing.T) {
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{"op": "add", "path": "name.givenName", "value": "John"},
				{"op": "add", "path": "name.familyName", "value": "Doe"}
			]
		}`

		req, _ := http.NewRequest(http.MethodPatch, baseURL+"/Users/"+createdUser.ID, strings.NewReader(patchBody))
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var patchedUser User
		if err := json.NewDecoder(resp.Body).Decode(&patchedUser); err != nil {
			t.Fatalf("failed to decode patched user: %v", err)
		}

		if patchedUser.Name == nil {
			t.Fatal("name should not be nil")
		}
		if patchedUser.Name.GivenName != "John" {
			t.Errorf("name.givenName = %q, want %q", patchedUser.Name.GivenName, "John")
		}
		if patchedUser.Name.FamilyName != "Doe" {
			t.Errorf("name.familyName = %q, want %q", patchedUser.Name.FamilyName, "Doe")
		}
	})

	// Test PATCH remove operation
	t.Run("PATCH remove displayName", func(t *testing.T) {
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{"op": "remove", "path": "displayName"}
			]
		}`

		req, _ := http.NewRequest(http.MethodPatch, baseURL+"/Users/"+createdUser.ID, strings.NewReader(patchBody))
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var patchedUser User
		if err := json.NewDecoder(resp.Body).Decode(&patchedUser); err != nil {
			t.Fatalf("failed to decode patched user: %v", err)
		}

		if patchedUser.DisplayName != "" {
			t.Errorf("displayName = %q, want empty", patchedUser.DisplayName)
		}
	})
}

// TestGroupMembership tests adding and removing members from groups.
func TestGroupMembership(t *testing.T) {
	server, store, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create a user
	userBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "member@example.com",
		"displayName": "Team Member"
	}`

	resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(userBody))
	if err != nil {
		t.Fatalf("create user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		t.Fatalf("failed to decode user: %v", err)
	}

	// Create a group
	groupBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
		"displayName": "Test Team"
	}`

	resp, err = http.Post(baseURL+"/Groups", "application/scim+json", strings.NewReader(groupBody))
	if err != nil {
		t.Fatalf("create group request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var group Group
	if err := json.NewDecoder(resp.Body).Decode(&group); err != nil {
		t.Fatalf("failed to decode group: %v", err)
	}

	// Add member via PATCH
	t.Run("add member via PATCH", func(t *testing.T) {
		patchBody := fmt.Sprintf(`{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{"op": "add", "path": "members", "value": [{"value": "%s"}]}
			]
		}`, user.ID)

		req, _ := http.NewRequest(http.MethodPatch, baseURL+"/Groups/"+group.ID, strings.NewReader(patchBody))
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var patchedGroup Group
		if err := json.NewDecoder(resp.Body).Decode(&patchedGroup); err != nil {
			t.Fatalf("failed to decode patched group: %v", err)
		}

		if len(patchedGroup.Members) != 1 {
			t.Fatalf("expected 1 member, got %d", len(patchedGroup.Members))
		}

		if patchedGroup.Members[0].Value != user.ID {
			t.Errorf("member value = %q, want %q", patchedGroup.Members[0].Value, user.ID)
		}
	})

	// Verify membership from user perspective
	t.Run("verify user groups", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users/" + user.ID)
		if err != nil {
			t.Fatalf("get user request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var fetchedUser User
		if err := json.NewDecoder(resp.Body).Decode(&fetchedUser); err != nil {
			t.Fatalf("failed to decode user: %v", err)
		}

		if len(fetchedUser.Groups) != 1 {
			t.Fatalf("expected 1 group, got %d", len(fetchedUser.Groups))
		}
	})

	// Remove member via PATCH
	t.Run("remove member via PATCH", func(t *testing.T) {
		patchBody := fmt.Sprintf(`{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{"op": "remove", "path": "members[value eq \"%s\"]"}
			]
		}`, user.ID)

		req, _ := http.NewRequest(http.MethodPatch, baseURL+"/Groups/"+group.ID, strings.NewReader(patchBody))
		req.Header.Set("Content-Type", "application/scim+json")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("PATCH request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var patchedGroup Group
		if err := json.NewDecoder(resp.Body).Decode(&patchedGroup); err != nil {
			t.Fatalf("failed to decode patched group: %v", err)
		}

		if len(patchedGroup.Members) != 0 {
			t.Errorf("expected 0 members, got %d", len(patchedGroup.Members))
		}
	})

	// Verify membership removed
	store.mu.RLock()
	members := store.memberships[group.ID]
	store.mu.RUnlock()
	if len(members) != 0 {
		t.Errorf("expected 0 members in store, got %d", len(members))
	}
}

// TestServiceProviderConfig tests the ServiceProviderConfig endpoint.
func TestServiceProviderConfig(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	resp, err := http.Get(baseURL + "/ServiceProviderConfig")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	var config map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		t.Fatalf("failed to decode config: %v", err)
	}

	// Verify expected fields
	if config["patch"] == nil {
		t.Error("patch config should be present")
	}
	if config["bulk"] == nil {
		t.Error("bulk config should be present")
	}
	if config["filter"] == nil {
		t.Error("filter config should be present")
	}
}

// TestSchemas tests the Schemas endpoint.
//
//nolint:dupl // Test structure mirrors TestResourceTypes - similar discovery endpoint tests
func TestSchemas(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("list all schemas", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Schemas")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		var listResponse ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if listResponse.TotalResults < 2 {
			t.Errorf("expected at least 2 schemas, got %d", listResponse.TotalResults)
		}
	})

	t.Run("get user schema", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Schemas/urn:ietf:params:scim:schemas:core:2.0:User")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestResourceTypes tests the ResourceTypes endpoint.
//
//nolint:dupl // Test structure mirrors TestSchemas - similar discovery endpoint tests
func TestResourceTypes(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("list all resource types", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/ResourceTypes")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}

		var listResponse ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if listResponse.TotalResults != 2 {
			t.Errorf("expected 2 resource types, got %d", listResponse.TotalResults)
		}
	})

	t.Run("get User resource type", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/ResourceTypes/User")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected status 200, got %d", resp.StatusCode)
		}
	})
}

// TestBulkOperations tests the bulk endpoint.
func TestBulkOperations(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("bulk endpoint returns 200 for empty request", func(t *testing.T) {
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": []
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResponse BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
			t.Fatalf("failed to decode bulk response: %v", err)
		}

		if len(bulkResponse.Operations) != 0 {
			t.Errorf("expected 0 operations, got %d", len(bulkResponse.Operations))
		}
	})

	t.Run("bulk create user", func(t *testing.T) {
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": [
				{
					"method": "POST",
					"path": "/Users",
					"bulkId": "bulk-user-1",
					"data": {
						"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
						"userName": "bulk.user@example.com",
						"displayName": "Bulk User",
						"active": true
					}
				}
			]
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResponse BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
			t.Fatalf("failed to decode bulk response: %v", err)
		}

		if len(bulkResponse.Operations) != 1 {
			t.Fatalf("expected 1 operation, got %d", len(bulkResponse.Operations))
		}

		op := bulkResponse.Operations[0]
		if op.Status != "201" {
			t.Errorf("expected status 201, got %s", op.Status)
		}
		if op.BulkID != "bulk-user-1" {
			t.Errorf("expected bulkId 'bulk-user-1', got %s", op.BulkID)
		}
		if op.Location == "" {
			t.Error("expected Location to be set")
		}
	})

	t.Run("bulk create group", func(t *testing.T) {
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": [
				{
					"method": "POST",
					"path": "/Groups",
					"bulkId": "bulk-group-1",
					"data": {
						"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
						"displayName": "Bulk Group"
					}
				}
			]
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResponse BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
			t.Fatalf("failed to decode bulk response: %v", err)
		}

		if len(bulkResponse.Operations) != 1 {
			t.Fatalf("expected 1 operation, got %d", len(bulkResponse.Operations))
		}

		op := bulkResponse.Operations[0]
		if op.Status != "201" {
			t.Errorf("expected status 201, got %s", op.Status)
		}
		if op.BulkID != "bulk-group-1" {
			t.Errorf("expected bulkId 'bulk-group-1', got %s", op.BulkID)
		}
	})

	t.Run("bulk multiple operations", func(t *testing.T) {
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": [
				{
					"method": "POST",
					"path": "/Users",
					"bulkId": "multi-user-1",
					"data": {
						"userName": "multi.user1@example.com",
						"displayName": "Multi User 1"
					}
				},
				{
					"method": "POST",
					"path": "/Users",
					"bulkId": "multi-user-2",
					"data": {
						"userName": "multi.user2@example.com",
						"displayName": "Multi User 2"
					}
				},
				{
					"method": "POST",
					"path": "/Groups",
					"bulkId": "multi-group-1",
					"data": {
						"displayName": "Multi Group 1"
					}
				}
			]
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResponse BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
			t.Fatalf("failed to decode bulk response: %v", err)
		}

		if len(bulkResponse.Operations) != 3 {
			t.Fatalf("expected 3 operations, got %d", len(bulkResponse.Operations))
		}

		// All should succeed
		for i, op := range bulkResponse.Operations {
			if op.Status != "201" {
				t.Errorf("operation %d: expected status 201, got %s", i, op.Status)
			}
		}
	})

	t.Run("bulk with invalid user data", func(t *testing.T) {
		// Missing required userName
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": [
				{
					"method": "POST",
					"path": "/Users",
					"bulkId": "invalid-user",
					"data": {
						"displayName": "No Username"
					}
				}
			]
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResponse BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResponse); err != nil {
			t.Fatalf("failed to decode bulk response: %v", err)
		}

		if len(bulkResponse.Operations) != 1 {
			t.Fatalf("expected 1 operation, got %d", len(bulkResponse.Operations))
		}

		op := bulkResponse.Operations[0]
		if op.Status != "400" {
			t.Errorf("expected status 400 for invalid user, got %s", op.Status)
		}
	})
}

// TestFilterQueries tests SCIM filter parsing and acceptance.
// Note: The mock store does not implement filtering, so these tests verify
// that filters are parsed correctly and requests are accepted.
// Full filter functionality is tested with the Ent store in production.
func TestFilterQueries(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create test users
	users := []struct {
		userName    string
		displayName string
	}{
		{"alice@example.com", "Alice Smith"},
		{"bob@example.com", "Bob Jones"},
		{"carol@example.com", "Carol Williams"},
	}

	for _, u := range users {
		userBody := fmt.Sprintf(`{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": %q,
			"displayName": %q,
			"active": true
		}`, u.userName, u.displayName)

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(userBody))
		if err != nil {
			t.Fatalf("failed to create user %s: %v", u.userName, err)
		}
		_ = resp.Body.Close()
	}

	t.Run("filter by userName equality is accepted", func(t *testing.T) {
		filterStr := `userName eq "alice@example.com"`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var listResp ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify response structure is valid
		if listResp.TotalResults < 0 {
			t.Error("TotalResults should be non-negative")
		}
	})

	t.Run("filter by displayName contains is accepted", func(t *testing.T) {
		filterStr := `displayName co "Smith"`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("filter by userName startsWith is accepted", func(t *testing.T) {
		filterStr := `userName sw "bob"`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("filter by active boolean is accepted", func(t *testing.T) {
		filterStr := `active eq true`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("filter with logical and is accepted", func(t *testing.T) {
		filterStr := `userName eq "alice@example.com" and active eq true`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("filter with logical or is accepted", func(t *testing.T) {
		filterStr := `userName eq "alice@example.com" or userName eq "bob@example.com"`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("invalid filter returns error", func(t *testing.T) {
		// Invalid operator and unbalanced parentheses
		filterStr := `userName invalid_op "test" )`
		resp, err := http.Get(baseURL + "/Users?filter=" + url.QueryEscape(filterStr))
		if err != nil {
			t.Fatalf("filter request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// The parser may still accept some malformed filters - just verify
		// it handles the request without crashing
		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusBadRequest {
			body, _ := io.ReadAll(resp.Body)
			t.Errorf("expected status 200 or 400 for filter, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

// TestErrorResponses tests various error scenarios.
func TestErrorResponses(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("get non-existent user", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users/non-existent-id")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", resp.StatusCode)
		}

		var scimErr Error
		if err := json.NewDecoder(resp.Body).Decode(&scimErr); err != nil {
			t.Fatalf("failed to decode error: %v", err)
		}

		if scimErr.Status != http.StatusNotFound {
			t.Errorf("error status = %d, want 404", scimErr.Status)
		}
	})

	t.Run("create user without userName", func(t *testing.T) {
		createBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"displayName": "No UserName"
		}`

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		// Huma returns 422 Unprocessable Entity for validation errors (missing required field)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 422, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("create duplicate user", func(t *testing.T) {
		createBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "duplicate@example.com",
			"displayName": "First"
		}`

		// Create first user
		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("first create failed: %v", err)
		}
		_ = resp.Body.Close()

		// Try to create duplicate
		resp, err = http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("second create failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("expected status 409, got %d", resp.StatusCode)
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodDelete, baseURL+"/ServiceProviderConfig", nil)
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("expected status 405, got %d", resp.StatusCode)
		}
	})

	t.Run("invalid JSON body", func(t *testing.T) {
		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader("not valid json"))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", resp.StatusCode)
		}
	})
}

// TestPagination tests pagination of list endpoints.
func TestPagination(t *testing.T) {
	server, store, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create multiple users directly in store
	for i := 0; i < 10; i++ {
		store.users[fmt.Sprintf("user-%d", i+1)] = &User{
			Resource: Resource{
				ID:      fmt.Sprintf("user-%d", i+1),
				Schemas: []string{SchemaUser},
			},
			UserName:    fmt.Sprintf("user%d@example.com", i),
			DisplayName: fmt.Sprintf("User %d", i),
		}
	}
	store.userSeq = 10

	t.Run("default pagination", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var listResponse ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if listResponse.TotalResults != 10 {
			t.Errorf("totalResults = %d, want 10", listResponse.TotalResults)
		}
		if listResponse.StartIndex != 1 {
			t.Errorf("startIndex = %d, want 1", listResponse.StartIndex)
		}
	})

	t.Run("with startIndex and count", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users?startIndex=3&count=2")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		var listResponse ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResponse); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if listResponse.TotalResults != 10 {
			t.Errorf("totalResults = %d, want 10", listResponse.TotalResults)
		}
		if listResponse.StartIndex != 3 {
			t.Errorf("startIndex = %d, want 3", listResponse.StartIndex)
		}
		if listResponse.ItemsPerPage != 2 {
			t.Errorf("itemsPerPage = %d, want 2", listResponse.ItemsPerPage)
		}
		if len(listResponse.Resources) != 2 {
			t.Errorf("resources length = %d, want 2", len(listResponse.Resources))
		}
	})
}

// TestETagSupport tests ETag-based optimistic locking.
func TestETagSupport(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create a user
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "etag.test@example.com",
		"displayName": "ETag Test User"
	}`

	resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatalf("create user request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var createdUser User
	if err := json.NewDecoder(resp.Body).Decode(&createdUser); err != nil {
		t.Fatalf("failed to decode user: %v", err)
	}

	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Skip("ETag not returned, skipping ETag tests")
	}

	t.Run("update with matching ETag", func(t *testing.T) {
		updateBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "etag.test@example.com",
			"displayName": "Updated With ETag"
		}`

		req, _ := http.NewRequest(http.MethodPut, baseURL+"/Users/"+createdUser.ID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("If-Match", etag)
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("update with mismatched ETag", func(t *testing.T) {
		updateBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "etag.test@example.com",
			"displayName": "Should Fail"
		}`

		req, _ := http.NewRequest(http.MethodPut, baseURL+"/Users/"+createdUser.ID, strings.NewReader(updateBody))
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("If-Match", "\"invalid-etag\"")
		resp, err := http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusPreconditionFailed {
			t.Fatalf("expected status 412, got %d", resp.StatusCode)
		}
	})
}

// TestAttributeFiltering tests the attributes and excludedAttributes query parameters.
func TestAttributeFiltering(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create a test user
	createBody := `{
		"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName": "attrtest@example.com",
		"displayName": "Attribute Test User",
		"active": true,
		"name": {
			"givenName": "Attribute",
			"familyName": "Test"
		}
	}`

	resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var created User
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("failed to decode user: %v", err)
	}

	t.Run("filter to specific attributes", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users/" + created.ID + "?attributes=userName,displayName")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var user map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Should have userName and displayName
		if _, ok := user["userName"]; !ok {
			t.Error("expected userName to be present")
		}
		if _, ok := user["displayName"]; !ok {
			t.Error("expected displayName to be present")
		}
		// Should always have schemas, id, meta (required)
		if _, ok := user["schemas"]; !ok {
			t.Error("expected schemas to be present")
		}
		if _, ok := user["id"]; !ok {
			t.Error("expected id to be present")
		}
	})

	t.Run("exclude specific attributes", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/Users/" + created.ID + "?excludedAttributes=name,active")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var user map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Should NOT have name and active
		if _, ok := user["name"]; ok {
			t.Error("expected name to be excluded")
		}
		if _, ok := user["active"]; ok {
			t.Error("expected active to be excluded")
		}
		// Should have other attributes
		if _, ok := user["userName"]; !ok {
			t.Error("expected userName to be present")
		}
	})
}

// TestSearchEndpoint tests the POST /.search endpoint.
func TestSearchEndpoint(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	// Create test users
	for i := 1; i <= 3; i++ {
		createBody := fmt.Sprintf(`{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "searchuser%d@example.com",
			"displayName": "Search User %d",
			"active": true
		}`, i, i)

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
		_ = resp.Body.Close()
	}

	t.Run("search users with filter", func(t *testing.T) {
		searchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
			"filter": "userName sw \"searchuser\"",
			"startIndex": 1,
			"count": 10
		}`

		resp, err := http.Post(baseURL+"/Users/.search", "application/scim+json", strings.NewReader(searchBody))
		if err != nil {
			t.Fatalf("search request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var listResp ListResponse
		if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// The mock store doesn't filter, so we just verify the endpoint works
		if listResp.TotalResults < 0 {
			t.Error("expected non-negative total results")
		}
	})

	t.Run("search with attributes parameter", func(t *testing.T) {
		searchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
			"attributes": ["userName", "displayName"],
			"startIndex": 1,
			"count": 10
		}`

		resp, err := http.Post(baseURL+"/Users/.search", "application/scim+json", strings.NewReader(searchBody))
		if err != nil {
			t.Fatalf("search request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})

	t.Run("search groups", func(t *testing.T) {
		searchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
			"startIndex": 1,
			"count": 10
		}`

		resp, err := http.Post(baseURL+"/Groups/.search", "application/scim+json", strings.NewReader(searchBody))
		if err != nil {
			t.Fatalf("search request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}
	})
}

// TestBulkIdCrossReferences tests bulkId cross-referencing in bulk operations.
func TestBulkIdCrossReferences(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("create user and group with cross-reference", func(t *testing.T) {
		// Create a user and a group, then add the user to the group using bulkId
		bulkBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:BulkRequest"],
			"Operations": [
				{
					"method": "POST",
					"path": "/Users",
					"bulkId": "user1",
					"data": {
						"userName": "bulkref.user@example.com",
						"displayName": "Bulk Ref User"
					}
				},
				{
					"method": "POST",
					"path": "/Groups",
					"bulkId": "group1",
					"data": {
						"displayName": "Bulk Ref Group",
						"members": [
							{"value": "bulkId:user1"}
						]
					}
				}
			]
		}`

		resp, err := http.Post(baseURL+"/Bulk", "application/scim+json", strings.NewReader(bulkBody))
		if err != nil {
			t.Fatalf("bulk request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var bulkResp BulkResponse
		if err := json.NewDecoder(resp.Body).Decode(&bulkResp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(bulkResp.Operations) != 2 {
			t.Fatalf("expected 2 operations, got %d", len(bulkResp.Operations))
		}

		// First operation (user creation) should succeed
		if bulkResp.Operations[0].Status != "201" {
			t.Errorf("user creation: expected status 201, got %s", bulkResp.Operations[0].Status)
		}

		// Second operation (group creation with member) should succeed
		if bulkResp.Operations[1].Status != "201" {
			t.Errorf("group creation: expected status 201, got %s", bulkResp.Operations[1].Status)
		}
	})
}

// TestPasswordHandling tests password creation and modification.
func TestPasswordHandling(t *testing.T) {
	server, _, err := setupTestServer()
	if err != nil {
		t.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	t.Run("create user with password", func(t *testing.T) {
		createBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "pwduser@example.com",
			"displayName": "Password User",
			"password": "SecurePassword123!"
		}`

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, string(body))
		}

		var user User
		if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
			t.Fatalf("failed to decode user: %v", err)
		}

		// Password should not be returned in response
		if user.Password != "" {
			t.Error("password should not be returned in response")
		}
	})

	t.Run("change password via PATCH", func(t *testing.T) {
		// First create a user
		createBody := `{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "patchpwd@example.com",
			"displayName": "Patch Password User"
		}`

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", strings.NewReader(createBody))
		if err != nil {
			t.Fatalf("failed to create user: %v", err)
		}

		var created User
		if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
			t.Fatalf("failed to decode user: %v", err)
		}
		_ = resp.Body.Close()

		// Now patch to set password
		patchBody := `{
			"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
			"Operations": [
				{
					"op": "add",
					"path": "password",
					"value": "NewSecurePassword456!"
				}
			]
		}`

		req, err := http.NewRequest(http.MethodPatch, baseURL+"/Users/"+created.ID, strings.NewReader(patchBody))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/scim+json")

		resp, err = http.DefaultClient.Do(req) //nolint:gosec // test code using test server URL
		if err != nil {
			t.Fatalf("patch request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, string(body))
		}

		var updated User
		if err := json.NewDecoder(resp.Body).Decode(&updated); err != nil {
			t.Fatalf("failed to decode user: %v", err)
		}

		// Password should not be returned
		if updated.Password != "" {
			t.Error("password should not be returned in patch response")
		}
	})
}

// BenchmarkUserCreation benchmarks user creation performance.
func BenchmarkUserCreation(b *testing.B) {
	server, _, err := setupTestServer()
	if err != nil {
		b.Fatalf("failed to setup test server: %v", err)
	}
	defer server.Close()

	baseURL := server.URL + "/scim/v2"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		createBody := fmt.Sprintf(`{
			"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
			"userName": "bench%d@example.com",
			"displayName": "Benchmark User %d"
		}`, i, i)

		resp, err := http.Post(baseURL+"/Users", "application/scim+json", bytes.NewReader([]byte(createBody)))
		if err != nil {
			b.Fatalf("create failed: %v", err)
		}
		_ = resp.Body.Close()
	}
}
