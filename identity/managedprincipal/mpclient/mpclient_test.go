package mpclient_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3" // SQLite driver for enttest

	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/managedprincipal"
	"github.com/plexusone/systemforge/identity/managedprincipal/mpclient"
	"github.com/plexusone/systemforge/identity/requestprincipal"
	"github.com/plexusone/systemforge/session/ratelimit"
)

const appClient = "app"

type gate struct{}

func (gate) ManagedPrincipalsAllowed(_ context.Context, clientID string) (bool, error) {
	return clientID == appClient, nil
}

func (gate) LoginTokenPolicy(context.Context, string) (credential.LoginTokenPolicy, error) {
	return credential.LoginTokenPolicy{}, nil
}

// fixture serves the managed-principal API in relying-party mode. A bearer
// token is "<principal ID>:<client ID>", standing in for SystemAuth's
// access tokens.
type fixture struct {
	db  *ent.Client
	api *mpclient.Client
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	rates := ratelimit.NewMemoryStorage()
	t.Cleanup(func() {
		if err := rates.Close(); err != nil {
			t.Error(err)
		}
	})
	h := managedprincipal.NewHandler(managedprincipal.NewService(db, gate{}),
		managedprincipal.WithRequestClient(managedprincipal.RequestClientFromPrincipal),
		managedprincipal.WithCodeRateLimit(rates, ratelimit.Limit{Rate: 3, Period: time.Minute}))
	auth := requestprincipal.Middleware(requestprincipal.Options{}, requestprincipal.AuthenticatorFunc(
		func(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
			tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			id, clientID, found := strings.Cut(tok, ":")
			if !ok || !found {
				return nil, &requestprincipal.Error{Status: http.StatusUnauthorized}
			}
			return &requestprincipal.RequestPrincipal{PrincipalID: id, Claims: map[string]any{"client_id": clientID}}, nil
		}))
	mux := http.NewServeMux()
	mux.Handle("/managed-principals/", http.StripPrefix("/managed-principals", auth(h)))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fixture{db: db, api: mpclient.New(srv.URL+"/managed-principals/", srv.Client())}
}

func (f *fixture) human(t *testing.T, email string) (uuid.UUID, string) {
	t.Helper()
	ctx := context.Background()
	id := uuid.New()
	if _, err := f.db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier(email).SetDisplayName("H").SetActive(true).Save(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Human.Create().SetPrincipalID(id).SetEmail(email).SetEmailVerifiedAt(time.Now()).Save(ctx); err != nil {
		t.Fatal(err)
	}
	return id, id.String() + ":" + appClient
}

func TestClientManagesAPrincipal(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	teacher, teacherTok := f.human(t, "teacher@example.com")
	_, parentTok := f.human(t, "parent@example.com")

	id, err := f.api.Create(ctx, teacherTok, mpclient.CreateInput{DisplayName: "Robin", Role: mpclient.RoleEducator})
	if err != nil {
		t.Fatal(err)
	}
	list, err := f.api.List(ctx, teacherTok, uuid.Nil, 0)
	if err != nil || len(list) != 1 || list[0].PrincipalID != id || list[0].DisplayName != "Robin" {
		t.Fatalf("list %+v %v", list, err)
	}
	if page, err := f.api.List(ctx, teacherTok, id, 10); err != nil || len(page) != 0 {
		t.Fatalf("page after the last: %+v %v", page, err)
	}

	issued, err := f.api.IssueLoginToken(ctx, teacherTok, id, mpclient.IssueLoginTokenInput{Name: "card"})
	if err != nil || issued.Token == "" {
		t.Fatalf("issue %+v %v", issued, err)
	}
	tokens, err := f.api.ListLoginTokens(ctx, teacherTok, id)
	if err != nil || len(tokens) != 1 || tokens[0].ID != issued.ID || tokens[0].Name != "card" {
		t.Fatalf("tokens %+v %v", tokens, err)
	}
	if err := f.api.RevokeLoginToken(ctx, teacherTok, id, issued.ID); err != nil {
		t.Fatal(err)
	}
	if sessions, err := f.api.ListSessions(ctx, teacherTok, id); err != nil || len(sessions) != 0 {
		t.Fatalf("sessions %+v %v", sessions, err)
	}
	if err := f.api.RevokeAll(ctx, teacherTok, id); err != nil {
		t.Fatal(err)
	}

	// A parent claims the principal and becomes its guardian.
	claim, err := f.api.IssueClaim(ctx, teacherTok, id)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.api.RedeemClaim(ctx, parentTok, claim.Code); err != nil || got != id {
		t.Fatalf("redeem %s %v", got, err)
	}
	managers, err := f.api.ListManagers(ctx, teacherTok, id)
	if err != nil || len(managers) != 2 {
		t.Fatalf("managers %+v %v", managers, err)
	}
	if err := f.api.RemoveManager(ctx, parentTok, id, teacher, mpclient.RoleEducator); err != nil {
		t.Fatal(err)
	}
	if err := f.api.Delete(ctx, parentTok, id); err != nil {
		t.Fatal(err)
	}
}

func TestClientErrors(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, teacherTok := f.human(t, "teacher@example.com")
	outsider, outsiderTok := f.human(t, "outsider@example.com")
	id, err := f.api.Create(ctx, teacherTok, mpclient.CreateInput{DisplayName: "Robin", Role: mpclient.RoleEducator})
	if err != nil {
		t.Fatal(err)
	}

	var apiErr *mpclient.APIError
	for name, tc := range map[string]struct {
		err  error
		want error
	}{
		"no token": {func() error { _, err := f.api.List(ctx, "", uuid.Nil, 0); return err }(), mpclient.ErrUnauthorized},
		"stranger": {func() error { _, err := f.api.ListLoginTokens(ctx, outsiderTok, id); return err }(), mpclient.ErrForbidden},
		"unknown principal": {func() error {
			_, err := f.api.IssueLoginToken(ctx, teacherTok, uuid.New(), mpclient.IssueLoginTokenInput{})
			return err
		}(), mpclient.ErrForbidden},
		"other client": {func() error {
			_, err := f.api.Create(ctx, outsider.String()+":other", mpclient.CreateInput{DisplayName: "X", Role: mpclient.RoleGuardian})
			return err
		}(), mpclient.ErrForbidden},
		"missing name": {func() error {
			_, err := f.api.Create(ctx, teacherTok, mpclient.CreateInput{Role: mpclient.RoleGuardian})
			return err
		}(), mpclient.ErrInvalidRequest},
		"bad code": {func() error { _, err := f.api.RedeemClaim(ctx, outsiderTok, "nope"); return err }(), mpclient.ErrInvalidCode},
		"last manager": {func() error {
			guardian, guardianTok := f.human(t, "guardian@example.com")
			gid, err := f.api.Create(ctx, guardianTok, mpclient.CreateInput{DisplayName: "Sam", Role: mpclient.RoleGuardian})
			if err != nil {
				return err
			}
			return f.api.RemoveManager(ctx, guardianTok, gid, guardian, mpclient.RoleGuardian)
		}(), mpclient.ErrConflict},
	} {
		if !errors.Is(tc.err, tc.want) || !errors.As(tc.err, &apiErr) {
			t.Errorf("%s: %v, want %v", name, tc.err, tc.want)
		}
	}

	// Two more bad codes reach the limit of three.
	for range 2 {
		if _, err := f.api.RedeemClaim(ctx, outsiderTok, "nope"); !errors.Is(err, mpclient.ErrInvalidCode) {
			t.Fatalf("bad code: %v", err)
		}
	}
	_, err = f.api.RedeemClaim(ctx, outsiderTok, "nope")
	if !errors.Is(err, mpclient.ErrRateLimited) || !errors.As(err, &apiErr) || apiErr.RetryAfter <= 0 {
		t.Fatalf("rate limited: %v", err)
	}
}
