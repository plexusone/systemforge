package invite_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/identity/invite"
	"github.com/plexusone/systemforge/identity/organization"
)

const leakText = `pq: relation "secret_invites" does not exist`

// failingService fails the calls the API makes after its access checks
// with an internal error.
type failingService struct {
	invite.Service
}

func (failingService) List(context.Context, invite.ListInvitesInput) ([]*invite.Invite, error) {
	return nil, errors.New(leakText)
}

func (failingService) Revoke(context.Context, uuid.UUID) error {
	return errors.New(leakText)
}

func (failingService) Create(context.Context, invite.CreateInviteInput) (*invite.InviteResult, error) {
	return nil, errors.New(leakText)
}

// TestInternalErrorsDoNotLeak expects an internal service error to be
// logged and answered with a generic 500 that does not carry its text.
func TestInternalErrorsDoNotLeak(t *testing.T) {
	a := newInviteAPI(t)
	var logs bytes.Buffer
	cfg := invite.DefaultAPIConfig()
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	cfg.Authorizer = rbac.New(rbac.WithRoleGetter(organization.MembershipRoleGetter(a.orgs)))
	real := invite.NewService(a.db, "https://app.example.com")
	a.h = invite.NewAPI(failingService{Service: real}, a.orgs, cfg)

	// Revoke loads the invite through the real service first.
	created, err := real.Create(context.Background(), invite.CreateInviteInput{
		OrganizationID: a.org.ID, InviterPrincipalID: a.people["admin"], Email: "x@example.com", Role: "member",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/organizations/acme/invites", nil},
		{http.MethodPost, "/organizations/acme/invites", map[string]any{"email": "y@example.com", "role": "member"}},
		{http.MethodDelete, "/organizations/acme/invites/" + created.Invite.ID.String(), nil},
	} {
		code, body := a.do(tc.method, tc.path, "admin", tc.body)
		if code != http.StatusInternalServerError {
			t.Errorf("%s %s = %d %s, want 500", tc.method, tc.path, code, body)
		}
		if strings.Contains(string(body), "secret_invites") {
			t.Errorf("%s %s response leaks the internal error: %s", tc.method, tc.path, body)
		}
	}
	if !strings.Contains(logs.String(), "secret_invites") {
		t.Errorf("internal error not logged: %s", logs.String())
	}
}

// TestClientErrorsKeepTheirMessage expects a known service error to keep
// a fixed, actionable message.
func TestClientErrorsKeepTheirMessage(t *testing.T) {
	a := newInviteAPI(t)
	a.invite("dup@example.com")
	code, body := a.do(http.MethodPost, "/organizations/acme/invites", "admin", map[string]any{"email": "dup@example.com", "role": "member"})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "pending invite already exists") {
		t.Errorf("duplicate invite = %d %s, want 400 with the pending-invite message", code, body)
	}
}
