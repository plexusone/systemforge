package managedprincipal

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/hook"
)

func TestReplaceLoginTokens(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	second, err := f.svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.teacher, Name: "spare"})
	if err != nil {
		t.Fatal(err)
	}

	// A guardian replaces the card the educator issued, and the spare.
	got, err := f.svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.parent, Name: "new card"})
	if err != nil {
		t.Fatalf("ReplaceLoginTokens: %v", err)
	}
	if got.Revoked != 2 || got.Token == nil || got.Token.PlainToken == "" {
		t.Fatalf("replaced %+v", got)
	}
	for _, old := range []string{f.plain, second.PlainToken} {
		if _, err := f.svc.creds.VerifyLoginToken(ctx, old, ""); err == nil {
			t.Error("a replaced token still verifies")
		}
	}
	if _, err := f.svc.creds.VerifyLoginToken(ctx, got.Token.PlainToken, ""); err != nil {
		t.Errorf("the new token does not verify: %v", err)
	}
	tokens, err := f.svc.ListLoginTokens(ctx, f.teacher, f.learner)
	if err != nil || len(tokens) != 1 || tokens[0].ID != got.Token.Credential.ID || tokens[0].Name != "new card" {
		t.Fatalf("tokens after replace = %+v, %v", tokens, err)
	}
	// Sessions signed in with an old token are left to RevokeAll.
	if sessions, err := f.svc.ListSessions(ctx, f.teacher, f.learner); err != nil || len(sessions) != 3 {
		t.Errorf("sessions after replace = %d, %v", len(sessions), err)
	}

	var ev map[string]any
	for _, e := range f.rec.events {
		if e.EventType == EventTokensReplaced {
			ev = e.Details
		}
	}
	if ev == nil || ev["revoked"] != 2 || ev["credential_id"] != got.Token.Credential.ID.String() {
		t.Errorf("replace audit details = %v", ev)
	}

	// With no live token, a replace just issues one, single-use with its
	// shorter default lifetime.
	if err := f.svc.RevokeLoginToken(ctx, f.parent, f.learner, got.Token.Credential.ID); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	once, err := f.svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.parent, SingleUse: true})
	if err != nil {
		t.Fatal(err)
	}
	exp := once.Token.Credential.ExpiresAt
	if once.Revoked != 0 || exp == nil || exp.After(before.Add(21*time.Minute)) {
		t.Errorf("single-use replace = revoked %d, expires %v", once.Revoked, exp)
	}
	at := time.Now().Add(7 * 24 * time.Hour)
	week, err := f.svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.parent, ExpiresAt: &at})
	if err != nil {
		t.Fatal(err)
	}
	if week.Revoked != 1 || !week.Token.Credential.ExpiresAt.Equal(at) {
		t.Errorf("replace with an expiry = revoked %d, expires %v, want %v", week.Revoked, week.Token.Credential.ExpiresAt, at)
	}
}

func TestReplaceLoginTokensFailureKeepsTheOldTokens(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	errCreate := errors.New("create refused")
	f.db.Credential.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CredentialFunc(func(ctx context.Context, m *ent.CredentialMutation) (ent.Value, error) {
			if m.Op().Is(ent.OpCreate) {
				return nil, errCreate
			}
			return next.Mutate(ctx, m)
		})
	})
	if _, err := f.svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.teacher}); !errors.Is(err, errCreate) {
		t.Fatalf("ReplaceLoginTokens = %v, want the create's error", err)
	}
	if _, err := f.svc.creds.VerifyLoginToken(ctx, f.plain, ""); err != nil {
		t.Errorf("the old token stopped working after a failed replace: %v", err)
	}
	for _, typ := range f.rec.types() {
		if typ == EventTokensReplaced {
			t.Error("a failed replace was audited as done")
		}
	}
}

func TestReplaceLoginTokensRefusals(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	for _, tc := range []struct {
		name string
		in   IssueLoginTokenInput
		want error
	}{
		{"not a manager", IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.stranger}, ErrNotManager},
		{"client not allowed", IssueLoginTokenInput{ManagedID: f.learner, ClientID: "other", IssuedBy: f.teacher}, ErrNotAllowed},
		{"unknown principal", IssueLoginTokenInput{ManagedID: uuid.New(), ClientID: client, IssuedBy: f.teacher}, ErrNotManaged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := f.svc.ReplaceLoginTokens(ctx, tc.in); !errors.Is(err, tc.want) {
				t.Errorf("ReplaceLoginTokens = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := f.svc.creds.VerifyLoginToken(ctx, f.plain, ""); err != nil {
		t.Errorf("a refused replace revoked the token: %v", err)
	}
}

func TestRemoteReplaceLoginTokens(t *testing.T) {
	db := openSQLite(t)
	svc, _ := newService(t, db)
	c := remoteCaller{t, NewHandler(svc, WithRequestClient(RequestClientFromPrincipal))}
	teacher := addVerifiedHuman(t, db, "teacher@example.com")
	outsider := addVerifiedHuman(t, db, "outsider@example.com")
	learner, err := svc.Create(context.Background(), CreateInput{ClientID: client, DisplayName: "Robin",
		Managers: []ManagerInput{{PrincipalID: teacher, Role: RoleEducator}}, ActorID: teacher})
	if err != nil {
		t.Fatal(err)
	}
	path := "/" + learner.String() + "/login-tokens/replace"

	expectStatus(t, c.do(uuid.Nil, client, http.MethodPost, path, IssueLoginTokenRequest{}), http.StatusUnauthorized)
	expectStatus(t, c.do(outsider, client, http.MethodPost, path, IssueLoginTokenRequest{}), http.StatusForbidden)
	past := time.Now().Add(-time.Hour)
	expectStatus(t, c.do(teacher, client, http.MethodPost, path, IssueLoginTokenRequest{ExpiresAt: &past}), http.StatusBadRequest)

	w := c.do(teacher, client, http.MethodPost, "/"+learner.String()+"/login-tokens", IssueLoginTokenRequest{Name: "card"})
	expectStatus(t, w, http.StatusCreated)
	var old IssuedLoginToken
	decodeBody(t, w, &old)

	w = c.do(teacher, client, http.MethodPost, path, IssueLoginTokenRequest{Name: "new card"})
	expectStatus(t, w, http.StatusCreated)
	var got ReplacedLoginTokens
	decodeBody(t, w, &got)
	if got.Revoked != 1 || got.Token == "" || got.ID == old.ID {
		t.Fatalf("replaced %+v", got)
	}
	if _, err := svc.creds.VerifyLoginToken(context.Background(), old.Token, ""); err == nil {
		t.Error("the old token still verifies")
	}
	if _, err := svc.creds.VerifyLoginToken(context.Background(), got.Token, ""); err != nil {
		t.Errorf("the new token does not verify: %v", err)
	}
}
