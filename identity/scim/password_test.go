package scim

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// recordingStore records the password each user write hands to the store.
type recordingStore struct {
	*mockStore
	passwords []string
}

// The recording store keeps and returns copies, as a database-backed store
// does, so the provider clearing a password in a response does not reach
// the stored hash.
func copyUser(u *User, err error) (*User, error) {
	if err != nil {
		return nil, err
	}
	c := *u
	return &c, nil
}

func (s *recordingStore) CreateUser(ctx context.Context, user *User) (*User, error) {
	s.passwords = append(s.passwords, user.Password)
	in := *user
	return copyUser(s.mockStore.CreateUser(ctx, &in))
}

func (s *recordingStore) UpdateUser(ctx context.Context, id string, user *User) (*User, error) {
	s.passwords = append(s.passwords, user.Password)
	in := *user
	return copyUser(s.mockStore.UpdateUser(ctx, id, &in))
}

func (s *recordingStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	return copyUser(s.mockStore.GetUserByID(ctx, id))
}

func (s *recordingStore) ListUsers(ctx context.Context, opts ListOptions) ([]*User, int, error) {
	users, total, err := s.mockStore.ListUsers(ctx, opts)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*User, len(users))
	for i, u := range users {
		c := *u
		out[i] = &c
	}
	return out, total, nil
}

// A password set through SCIM reaches the store only as a hash, on create,
// PATCH and PUT alike, and is never returned.
func TestPasswordsAreHashedOnEveryWrite(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig()
	st := &recordingStore{mockStore: newMockStore()}
	p, err := NewProvider(cfg, st, WithAuthorizationHook(AllowAllAuthorizationHook{}), WithPasswordHasher(&BcryptHasher{Cost: bcrypt.MinCost}))
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	svc := p.Service()

	isHashOf := func(stored, plain string) bool {
		return stored != plain && bcrypt.CompareHashAndPassword([]byte(stored), []byte(plain)) == nil
	}
	noPassword := func(op string, u *User) {
		t.Helper()
		if u.Password != "" {
			t.Errorf("%s returned a password: %q", op, u.Password)
		}
	}

	u, err := svc.CreateUser(ctx, &User{UserName: "ada@example.com", Password: "CreateSecret0"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	noPassword("create", u)
	if !isHashOf(st.passwords[0], "CreateSecret0") {
		t.Errorf("create stored %q", st.passwords[0])
	}
	createdHash := st.passwords[0]

	patched, err := svc.PatchUser(ctx, u.ID, &PatchRequest{Operations: []PatchOperation{{Op: "replace", Path: "password", Value: "PlainSecret1"}}}, "")
	if err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	noPassword("patch", patched)
	if got := st.passwords[1]; !isHashOf(got, "PlainSecret1") {
		t.Errorf("PATCH handed the store %q, want a hash", got)
	}
	patchHash := st.passwords[1]

	// A PATCH without a password keeps the stored hash as it is.
	if _, err := svc.PatchUser(ctx, u.ID, &PatchRequest{Operations: []PatchOperation{{Op: "replace", Path: "displayName", Value: "Ada"}}}, ""); err != nil {
		t.Fatalf("PatchUser: %v", err)
	}
	if got := st.passwords[2]; got != patchHash || got == createdHash {
		t.Errorf("PATCH without a password handed the store %q, want the stored hash", got)
	}

	put, err := svc.UpdateUser(ctx, u.ID, &User{UserName: "ada@example.com", Password: "PutSecret2"}, "")
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	noPassword("put", put)
	if got := st.passwords[3]; !isHashOf(got, "PutSecret2") {
		t.Errorf("PUT handed the store %q, want a hash", got)
	}

	got, err := svc.GetUser(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	noPassword("get", got)
	list, err := svc.ListUsers(ctx, ListOptions{})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	for _, r := range list.Resources {
		noPassword("list", r.(*User))
	}
}
