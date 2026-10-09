package token

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/internal/pgtest"
)

func openSQLite(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	return db
}

func addPrincipal(t *testing.T, db *ent.Client) uuid.UUID {
	t.Helper()
	p, err := db.Principal.Create().SetType(entprincipal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(context.Background())
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	return p.ID
}

func issueFor(t *testing.T, svc Service, pid uuid.UUID, mod func(*IssueInput)) *IssuedToken {
	t.Helper()
	in := IssueInput{PrincipalID: pid, PrincipalType: principal.TypeHuman, Scopes: []string{"read", "write"},
		AccessTTL: 10 * time.Minute, RefreshTTL: time.Hour}
	if mod != nil {
		mod(&in)
	}
	tok, err := svc.Issue(context.Background(), in)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return tok
}

func TestIssueAndValidate(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)

	tok := issueFor(t, svc, pid, nil)
	if tok.AccessToken == "" || tok.RefreshToken == "" || tok.TokenType != "Bearer" || tok.ExpiresIn != 600 {
		t.Fatalf("issued = %+v", tok)
	}
	row, err := db.PrincipalToken.Get(ctx, tok.Token.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if row.RefreshTokenSignature == nil {
		t.Fatal("no refresh token signature stored")
	}
	if row.AccessTokenSignature != signature(tok.AccessToken) || *row.RefreshTokenSignature != signature(tok.RefreshToken) ||
		strings.Contains(row.AccessTokenSignature+*row.RefreshTokenSignature, tok.AccessToken) {
		t.Error("tokens are not stored only as their hashes")
	}

	got, err := svc.Validate(ctx, tok.AccessToken)
	if err != nil || got.PrincipalID != pid {
		t.Fatalf("Validate = %+v, %v", got, err)
	}
	if row, err := db.PrincipalToken.Get(ctx, tok.Token.ID); err != nil || row.LastUsedAt == nil {
		t.Errorf("last use not recorded: %v", err)
	}
	if _, err := svc.Validate(ctx, tok.RefreshToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("refresh token as access token = %v", err)
	}
	if _, err := svc.Validate(ctx, "nope"); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("unknown token = %v", err)
	}

	// No refresh token without a refresh TTL; the default access TTL applies.
	short := issueFor(t, svc, pid, func(in *IssueInput) { in.RefreshTTL = 0; in.AccessTTL = 0 })
	if short.RefreshToken != "" || short.ExpiresIn != int(DefaultAccessTTL.Seconds()) {
		t.Errorf("issued without refresh = %+v", short)
	}

	// Expired and revoked tokens do not validate.
	if err := db.PrincipalToken.UpdateOneID(short.Token.ID).SetAccessExpiresAt(time.Now().Add(-time.Second)).Exec(ctx); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, err := svc.Validate(ctx, short.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("expired token = %v", err)
	}
	if err := svc.Revoke(ctx, tok.Token.ID, false, "logout"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Validate(ctx, tok.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("revoked token = %v", err)
	}
}

func TestRefreshRotates(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	first := issueFor(t, svc, pid, nil)
	firstRow, err := db.PrincipalToken.Get(ctx, first.Token.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken, Scopes: []string{"read"}})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if second.Token.FamilyID != first.Token.FamilyID || second.RefreshToken == first.RefreshToken {
		t.Errorf("refreshed = %+v", second.Token)
	}
	if len(second.Token.Scopes) != 1 || second.Token.Scopes[0] != "read" {
		t.Errorf("narrowed scopes = %v", second.Token.Scopes)
	}
	// The family's refresh expiry is kept; the access lifetime is the original.
	if second.Token.RefreshExpiresAt == nil || !second.Token.RefreshExpiresAt.Equal(*firstRow.RefreshExpiresAt) {
		t.Errorf("refresh expiry %v, want the family's %v", second.Token.RefreshExpiresAt, firstRow.RefreshExpiresAt)
	}
	if second.ExpiresIn < 590 || second.ExpiresIn > 600 {
		t.Errorf("access lifetime %ds, want the original 600s", second.ExpiresIn)
	}

	// The old pair is spent: its access token no longer validates.
	if _, err := svc.Validate(ctx, first.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("old access token after rotation = %v", err)
	}
	if _, err := svc.Validate(ctx, second.AccessToken); err != nil {
		t.Errorf("new access token: %v", err)
	}

	// Widening scopes is refused, and refusing does not spend the token.
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken, Scopes: []string{"admin"}}); !errors.Is(err, ErrScopeNotGranted) {
		t.Errorf("widened scope = %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken, Scopes: []string{"write"}}); !errors.Is(err, ErrScopeNotGranted) {
		t.Errorf("scope dropped earlier = %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken}); err != nil {
		t.Errorf("refresh after refused attempts: %v", err)
	}
}

// TestRefreshTokenReuseRevokesFamily verifies that presenting a rotated
// refresh token, the sign of a stolen copy, revokes the whole family.
func TestRefreshTokenReuseRevokesFamily(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	first := issueFor(t, svc, pid, nil)
	second, err := svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	_, err = svc.Refresh(ctx, RefreshInput{RefreshToken: first.RefreshToken})
	if !errors.Is(err, ErrRefreshTokenReused) || !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("reuse = %v, want ErrRefreshTokenReused", err)
	}
	if _, err := svc.Validate(ctx, second.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("family's current access token after reuse = %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: second.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("family's current refresh token after reuse = %v", err)
	}

	// Other families are untouched.
	other := issueFor(t, svc, pid, nil)
	if _, err := svc.Validate(ctx, other.AccessToken); err != nil {
		t.Errorf("another family: %v", err)
	}
}

// TestRefreshNeverExtendsTheSession verifies that a refresh near the end
// of the family's lifetime does not grant a fresh one.
func TestRefreshNeverExtendsTheSession(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	tok := issueFor(t, svc, pid, nil)
	end := time.Now().Add(2 * time.Minute)
	if err := db.PrincipalToken.UpdateOneID(tok.Token.ID).SetRefreshExpiresAt(end).Exec(ctx); err != nil {
		t.Fatalf("shorten: %v", err)
	}
	next, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tok.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if next.Token.RefreshExpiresAt == nil || next.Token.RefreshExpiresAt.Sub(end).Abs() > time.Second {
		t.Errorf("refresh expiry %v, want unchanged %v", next.Token.RefreshExpiresAt, end)
	}

	if err := db.PrincipalToken.UpdateOneID(next.Token.ID).SetRefreshExpiresAt(time.Now().Add(-time.Second)).Exec(ctx); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: next.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("expired refresh token = %v", err)
	}
}

func TestRefreshDPoPBinding(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	tok := issueFor(t, svc, pid, func(in *IssueInput) { in.DPoPJKT = "thumb-1" })

	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tok.RefreshToken}); !errors.Is(err, ErrDPoPMismatch) {
		t.Errorf("without the key = %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tok.RefreshToken, DPoPJKT: "thumb-2"}); !errors.Is(err, ErrDPoPMismatch) {
		t.Errorf("with another key = %v", err)
	}
	next, err := svc.Refresh(ctx, RefreshInput{RefreshToken: tok.RefreshToken, DPoPJKT: "thumb-1"})
	if err != nil || next.Token.DPoPJKT != "thumb-1" {
		t.Errorf("with the key = %+v, %v", next, err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: "unknown"}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("unknown refresh token = %v", err)
	}
}

func TestRevocation(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	a := issueFor(t, svc, pid, nil)
	a2, err := svc.Refresh(ctx, RefreshInput{RefreshToken: a.RefreshToken})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	b := issueFor(t, svc, pid, nil)

	if list, err := svc.ListForPrincipal(ctx, pid); err != nil || len(list) != 2 {
		t.Errorf("ListForPrincipal = %d, %v; want 2 live tokens", len(list), err)
	}

	// Revoking by signature with the family takes the whole rotation chain.
	row, err := db.PrincipalToken.Get(ctx, a2.Token.ID)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := svc.RevokeBySignature(ctx, row.AccessTokenSignature, true, "logout"); err != nil {
		t.Fatalf("RevokeBySignature: %v", err)
	}
	if _, err := svc.Validate(ctx, a2.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("revoked family token = %v", err)
	}
	if _, err := svc.Validate(ctx, b.AccessToken); err != nil {
		t.Errorf("unrelated token: %v", err)
	}
	if err := svc.RevokeBySignature(ctx, "unknown", false, "x"); err == nil {
		t.Error("revoking an unknown signature succeeded")
	}
	if err := svc.Revoke(ctx, uuid.New(), false, "x"); err == nil {
		t.Error("revoking an unknown token succeeded")
	}

	if err := svc.RevokeAllForPrincipal(ctx, pid, "account disabled"); err != nil {
		t.Fatalf("RevokeAllForPrincipal: %v", err)
	}
	if list, err := svc.ListForPrincipal(ctx, pid); err != nil || len(list) != 0 {
		t.Errorf("tokens after RevokeAllForPrincipal = %d, %v", len(list), err)
	}
}

func TestCapabilitiesForType(t *testing.T) {
	svc := &DefaultService{}
	if c := svc.GetCapabilitiesForType(principal.TypeHuman); !c.CanAccessUI {
		t.Errorf("human capabilities = %+v", c)
	}
	if c := svc.GetCapabilitiesForType(principal.TypeService); c.CanAccessUI {
		t.Errorf("service capabilities = %+v", c)
	}
}

// TestConcurrentRefresh verifies on PostgreSQL that a refresh token
// presented concurrently yields exactly one new token pair.
func TestConcurrentRefresh(t *testing.T) {
	ctx := context.Background()
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, pgtest.Open(t))))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	svc := NewService(db)
	pid := addPrincipal(t, db)

	for range 10 {
		tok := issueFor(t, svc, pid, nil)
		const n = 6
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = svc.Refresh(ctx, RefreshInput{RefreshToken: tok.RefreshToken})
			})
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrInvalidRefreshToken):
				t.Fatalf("Refresh: %v", err)
			}
		}
		if ok > 1 {
			t.Fatalf("successful refreshes = %d, want at most 1", ok)
		}
	}
}

// TestDeactivatedPrincipalLosesTokens verifies that a deactivated
// principal's tokens neither validate nor refresh, and stay revoked.
func TestDeactivatedPrincipalLosesTokens(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)
	a := issueFor(t, svc, pid, nil)
	b := issueFor(t, svc, pid, nil)

	if err := db.Principal.UpdateOneID(pid).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := svc.Validate(ctx, a.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("Validate for a deactivated principal = %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: b.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("Refresh for a deactivated principal = %v", err)
	}
	if err := db.Principal.UpdateOneID(pid).SetActive(true).Exec(ctx); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if _, err := svc.Validate(ctx, a.AccessToken); !errors.Is(err, ErrInvalidAccessToken) {
		t.Errorf("token revived by reactivation: %v", err)
	}
	if _, err := svc.Refresh(ctx, RefreshInput{RefreshToken: b.RefreshToken}); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Errorf("refresh token revived by reactivation: %v", err)
	}
}

// TestRevokeAllForPrincipalRecordsAccessChange verifies that revoking a
// principal's tokens records and announces an access change (ADR-010).
func TestRevokeAllForPrincipalRecordsAccessChange(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	var announced []accesschange.Change
	svc := NewService(db, WithAccessChangeSink(accesschange.SinkFunc(func(c accesschange.Change) { announced = append(announced, c) })))
	pid := addPrincipal(t, db)
	issueFor(t, svc, pid, nil)
	if err := svc.RevokeAllForPrincipal(ctx, pid, "test"); err != nil {
		t.Fatal(err)
	}
	if len(announced) != 1 || announced[0].PrincipalID != pid || announced[0].OrganizationID != nil || announced[0].Reason != accesschange.SessionsRevoked {
		t.Fatalf("announced = %+v", announced)
	}
	stored, err := accesschange.Since(ctx, db, time.Time{}, 0)
	if err != nil || len(stored) != 1 {
		t.Errorf("stored = %+v, %v", stored, err)
	}
}

// TestAccessTTLIsCapped verifies that a requested access lifetime above the
// ADR-010 maximum is lowered to it.
func TestAccessTTLIsCapped(t *testing.T) {
	db := openSQLite(t)
	svc := NewService(db)
	tok := issueFor(t, svc, addPrincipal(t, db), func(in *IssueInput) { in.AccessTTL = 24 * time.Hour })
	if want := int(accesschange.MaxAccessTokenLifetime.Seconds()); tok.ExpiresIn != want {
		t.Errorf("ExpiresIn = %d, want %d", tok.ExpiresIn, want)
	}
}
