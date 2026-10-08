package scim

import (
	"context"
	"errors"
	"testing"
)

// recordingHook records the operations it is asked about and allows only
// reads.
type recordingHook struct {
	AllowAllAuthorizationHook
	reads []string
}

func (h *recordingHook) CanRead(_ context.Context, resourceType, id string) error {
	h.reads = append(h.reads, resourceType+"/"+id)
	return nil
}

func (*recordingHook) CanCreate(context.Context, string) error { return ErrForbidden("read-only") }

func newAuthTestProvider(t *testing.T, opts ...ProviderOption) *Provider {
	t.Helper()
	config := DefaultConfig()
	p, err := NewProvider(config, newMockStore(), opts...)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	return p
}

// TestProviderDeniesEverythingByDefault verifies that a provider with no
// authorization hook exposes nothing, listings included.
func TestProviderDeniesEverythingByDefault(t *testing.T) {
	ctx := context.Background()
	svc := newAuthTestProvider(t).Service()
	var scimErr *Error
	if _, err := svc.ListUsers(ctx, ListOptions{}); !errors.As(err, &scimErr) || scimErr.Status != 403 {
		t.Errorf("ListUsers = %v, want 403", err)
	}
	if _, err := svc.ListGroups(ctx, ListOptions{}); !errors.As(err, &scimErr) || scimErr.Status != 403 {
		t.Errorf("ListGroups = %v, want 403", err)
	}
	if _, err := svc.CreateUser(ctx, &User{UserName: "a@example.com"}); err == nil {
		t.Error("CreateUser allowed with no authorization hook")
	}
	if _, err := svc.GetUser(ctx, "1"); err == nil {
		t.Error("GetUser allowed with no authorization hook")
	}
}

// TestListingsAreAuthorized verifies that listing users and groups asks
// the authorization hook, as every other read does.
func TestListingsAreAuthorized(t *testing.T) {
	ctx := context.Background()
	hook := &recordingHook{}
	svc := newAuthTestProvider(t, WithAuthorizationHook(hook)).Service()
	if _, err := svc.ListUsers(ctx, ListOptions{}); err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if _, err := svc.ListGroups(ctx, ListOptions{}); err != nil {
		t.Fatalf("ListGroups: %v", err)
	}
	if len(hook.reads) != 2 || hook.reads[0] != ResourceTypeUser+"/" || hook.reads[1] != ResourceTypeGroup+"/" {
		t.Errorf("hook was asked %v", hook.reads)
	}

	// A caller without the read scope gets nothing.
	scoped := newAuthTestProvider(t, WithAuthorizationHook(NewScopedAuthorizationHook(true))).Service()
	if _, err := scoped.ListUsers(ctx, ListOptions{}); err == nil {
		t.Error("a caller without scim:users:read listed users")
	}
}
