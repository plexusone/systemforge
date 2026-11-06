package managedprincipal

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/hook"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
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
	revokedFirst := false
	f.db.Credential.Use(func(next ent.Mutator) ent.Mutator {
		return hook.CredentialFunc(func(ctx context.Context, m *ent.CredentialMutation) (ent.Value, error) {
			if m.Op().Is(ent.OpCreate) {
				// The old token is revoked in the transaction before the
				// new one is created; the rollback undoes it.
				live, err := m.Client().Credential.Query().Where(liveLoginTokens(f.learner, time.Now())...).Count(ctx)
				if err != nil {
					return nil, err
				}
				revokedFirst = live == 0
				return nil, errCreate
			}
			return next.Mutate(ctx, m)
		})
	})
	if _, err := f.svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.teacher}); !errors.Is(err, errCreate) {
		t.Fatalf("ReplaceLoginTokens = %v, want the create's error", err)
	}
	if !revokedFirst {
		t.Error("the old token was still live in the transaction when the new one was created")
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

// racingGate stands in for a manager's removal committing between the
// client check and the issuing transaction: it runs removed when the token
// policy is read, which happens in between.
type racingGate struct {
	gate
	removed func()
}

func (g racingGate) LoginTokenPolicy(ctx context.Context, clientID string) (credential.LoginTokenPolicy, error) {
	g.removed()
	return g.gate.LoginTokenPolicy(ctx, clientID)
}

// TestIssuingRechecksTheIssuerUnderTheLock verifies that a manager removed
// after the client check but before the issuing transaction is refused,
// for both issuing and replacing, and that a refused replace keeps the
// principal's token.
func TestIssuingRechecksTheIssuerUnderTheLock(t *testing.T) {
	ctx := context.Background()
	f := newVisibilityFixture(t)
	remove := func() {
		if err := f.db.ManagerRelationship.Update().
			Where(managerrelationship.ManagedPrincipalID(f.learner), managerrelationship.ManagerPrincipalID(f.parent)).
			SetActive(false).Exec(ctx); err != nil {
			t.Fatalf("deactivate relationship: %v", err)
		}
	}
	svc := NewService(f.db, racingGate{gate: gate{client: true}, removed: remove}, WithDirectManagerAdds())
	in := IssueLoginTokenInput{ManagedID: f.learner, ClientID: client, IssuedBy: f.parent}
	if _, err := svc.IssueLoginToken(ctx, in); !errors.Is(err, ErrNotManager) {
		t.Errorf("IssueLoginToken by a manager removed meanwhile = %v, want %v", err, ErrNotManager)
	}
	if _, err := svc.ReplaceLoginTokens(ctx, in); !errors.Is(err, ErrNotManager) {
		t.Errorf("ReplaceLoginTokens by a manager removed meanwhile = %v, want %v", err, ErrNotManager)
	}
	if _, err := f.svc.creds.VerifyLoginToken(ctx, f.plain, ""); err != nil {
		t.Errorf("a refused replace revoked the token: %v", err)
	}
}

// TestConcurrentReplacesLeaveOneToken verifies on PostgreSQL that two
// managers replacing a principal's card at the same moment both succeed and
// leave exactly one live token: the second waits for the first's lock and
// revokes its token.
func TestConcurrentReplacesLeaveOneToken(t *testing.T) {
	ctx := context.Background()
	db := openPostgres(t)
	svc, _ := newService(t, db)
	for range 10 {
		a := addHuman(t, db, uuid.NewString()+"@example.com", true)
		b := addHuman(t, db, uuid.NewString()+"@example.com", true)
		id, err := svc.Create(ctx, CreateInput{ActorID: a, DisplayName: "Learner", ClientID: client,
			Managers: []ManagerInput{{a, RoleGuardian}, {b, RoleEducator}}})
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{ManagedID: id, ClientID: client, IssuedBy: a}); err != nil {
			t.Fatalf("IssueLoginToken: %v", err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		errs := make([]error, 2)
		for i, by := range []uuid.UUID{a, b} {
			wg.Go(func() {
				<-start
				_, errs[i] = svc.ReplaceLoginTokens(ctx, IssueLoginTokenInput{ManagedID: id, ClientID: client, IssuedBy: by})
			})
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("replace %d: %v", i, err)
			}
		}
		live, err := db.Credential.Query().Where(liveLoginTokens(id, time.Now())...).Count(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if live != 1 {
			t.Fatalf("live tokens after two concurrent replaces = %d, want 1", live)
		}
	}
}
