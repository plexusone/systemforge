package credential

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

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
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
	id := uuid.New()
	if _, err := db.Principal.Create().SetID(id).SetType(entprincipal.TypeHuman).
		SetIdentifier("human:" + id.String()).SetDisplayName("Learner").Save(context.Background()); err != nil {
		t.Fatalf("principal: %v", err)
	}
	return id
}

func issue(t *testing.T, svc Service, principalID uuid.UUID, exp time.Time, singleUse bool) *GeneratedLoginToken {
	t.Helper()
	tok, err := svc.IssueLoginToken(context.Background(), IssueLoginTokenInput{
		PrincipalID: principalID, IssuedBy: uuid.New(), ExpiresAt: exp, SingleUse: singleUse, Name: "card",
	})
	if err != nil {
		t.Fatalf("IssueLoginToken: %v", err)
	}
	return tok
}

func TestLoginTokenPolicyExpiresAt(t *testing.T) {
	now := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	day := 24 * time.Hour
	tests := []struct {
		name      string
		policy    LoginTokenPolicy
		requested *time.Time
		singleUse bool
		want      time.Time
		clamped   bool
		err       error
	}{
		{"platform default", LoginTokenPolicy{}, nil, false, now.Add(30 * day), false, nil},
		{"client default", LoginTokenPolicy{DefaultTTL: 300 * day}, nil, false, now.Add(300 * day), false, nil},
		{"client default clamped", LoginTokenPolicy{DefaultTTL: 500 * day}, nil, false, now.Add(400 * day), true, nil},
		{"explicit request wins", LoginTokenPolicy{DefaultTTL: 300 * day}, at(7 * day), false, now.Add(7 * day), false, nil},
		{"explicit request clamped", LoginTokenPolicy{}, at(401 * day), false, now.Add(400 * day), true, nil},
		{"custom ceiling", LoginTokenPolicy{MaxTTL: 10 * day}, nil, false, now.Add(10 * day), true, nil},
		{"single use ignores client default", LoginTokenPolicy{DefaultTTL: 300 * day}, nil, true, now.Add(20 * time.Minute), false, nil},
		{"single use custom", LoginTokenPolicy{SingleUseTTL: time.Hour}, nil, true, now.Add(time.Hour), false, nil},
		{"single use explicit", LoginTokenPolicy{}, at(2 * time.Hour), true, now.Add(2 * time.Hour), false, nil},
		{"past request", LoginTokenPolicy{}, at(-time.Minute), false, time.Time{}, false, ErrInvalidExpiry},
		{"now request", LoginTokenPolicy{}, at(0), false, time.Time{}, false, ErrInvalidExpiry},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, clamped, err := tt.policy.ExpiresAt(now, tt.requested, tt.singleUse)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v, want %v", err, tt.err)
			}
			if !got.Equal(tt.want) || clamped != tt.clamped {
				t.Errorf("ExpiresAt = %v, %v; want %v, %v", got, clamped, tt.want, tt.clamped)
			}
		})
	}
}

func TestIssueAndVerifyLoginToken(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)

	tok := issue(t, svc, pid, time.Now().Add(time.Hour), false)
	if !strings.HasPrefix(tok.PlainToken, LoginTokenPrefix) || tok.Prefix != tok.PlainToken[:12] {
		t.Errorf("token %q prefix %q", tok.PlainToken, tok.Prefix)
	}
	for _, r := range tok.PlainToken {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			t.Fatalf("token %q has %q, not QR alphanumeric", tok.PlainToken, r)
		}
	}
	if tok.Credential.Type != TypeLoginToken || tok.Credential.Name != "card" || LoginTokenSingleUse(tok.Credential) {
		t.Errorf("credential = %+v", tok.Credential)
	}
	row, err := db.Credential.Get(ctx, tok.Credential.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if strings.Contains(row.SecretHash, tok.PlainToken) || row.SecretHash == "" {
		t.Errorf("secret hash %q", row.SecretHash)
	}

	// Reusable: works repeatedly, also when typed by hand.
	typed := strings.ToLower(tok.PlainToken[:20]) + " - " + tok.PlainToken[20:]
	for _, plain := range []string{tok.PlainToken, tok.PlainToken, typed} {
		c, err := svc.VerifyLoginToken(ctx, plain, "203.0.113.7")
		if err != nil {
			t.Fatalf("VerifyLoginToken(%q): %v", plain, err)
		}
		if c.PrincipalID != pid || c.LastUsedAt == nil || c.LastUsedIP != "203.0.113.7" {
			t.Errorf("credential after verify = %+v", c)
		}
	}

	// Revoked tokens fail.
	if err := svc.Revoke(ctx, tok.Credential.ID, "lost card"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.VerifyLoginToken(ctx, tok.PlainToken, ""); !errors.Is(err, ErrInvalidLoginToken) {
		t.Errorf("revoked: %v", err)
	}
}

func TestVerifyLoginTokenFailuresAreIndistinguishable(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	pid := addPrincipal(t, db)

	good := issue(t, svc, pid, time.Now().Add(time.Hour), false)
	expired := issue(t, svc, pid, time.Now().Add(time.Hour), false)
	if err := db.Credential.UpdateOneID(expired.Credential.ID).SetExpiresAt(time.Now().Add(-time.Second)).Exec(ctx); err != nil {
		t.Fatalf("expire: %v", err)
	}
	inactive := issue(t, svc, pid, time.Now().Add(time.Hour), false)
	if err := db.Credential.UpdateOneID(inactive.Credential.ID).SetActive(false).Exec(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	// Right prefix, wrong secret.
	last := good.PlainToken[len(good.PlainToken)-1]
	swap := byte('A')
	if last == 'A' {
		swap = 'B'
	}
	forged := good.PlainToken[:len(good.PlainToken)-1] + string(swap)

	for name, plain := range map[string]string{
		"empty":     "",
		"prefix":    LoginTokenPrefix,
		"wrong":     "NOTATOKEN",
		"unknown":   LoginTokenPrefix + strings.Repeat("A", 52),
		"forged":    forged,
		"expired":   expired.PlainToken,
		"inactive":  inactive.PlainToken,
		"api key":   "sf_" + good.PlainToken,
		"truncated": good.PlainToken[:12],
	} {
		if _, err := svc.VerifyLoginToken(ctx, plain, ""); err != ErrInvalidLoginToken { //nolint:errorlint // the exact sentinel, unwrapped, is the contract
			t.Errorf("%s: err = %v, want exactly ErrInvalidLoginToken", name, err)
		}
	}
	if _, err := svc.IssueLoginToken(ctx, IssueLoginTokenInput{PrincipalID: pid}); !errors.Is(err, ErrInvalidExpiry) {
		t.Errorf("issue without expiry: %v", err)
	}
}

func TestLoginTokenIssuedBy(t *testing.T) {
	id := uuid.New()
	tests := []struct {
		meta    map[string]any
		want    uuid.UUID
		wantErr bool
	}{
		{map[string]any{metaIssuedBy: id.String()}, id, false},
		{map[string]any{}, uuid.Nil, false},
		{map[string]any{metaIssuedBy: 42}, uuid.Nil, true},
		{map[string]any{metaIssuedBy: "nope"}, uuid.Nil, true},
	}
	for _, tt := range tests {
		got, err := LoginTokenIssuedBy(&Credential{Metadata: tt.meta})
		if got != tt.want || (err != nil) != tt.wantErr {
			t.Errorf("LoginTokenIssuedBy(%v) = %v, %v", tt.meta, got, err)
		}
	}
}

func TestSingleUseLoginToken(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc := NewService(db)
	tok := issue(t, svc, addPrincipal(t, db), time.Now().Add(time.Minute), true)
	if !LoginTokenSingleUse(tok.Credential) {
		t.Fatal("not single use")
	}
	if _, err := svc.VerifyLoginToken(ctx, tok.PlainToken, ""); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := svc.VerifyLoginToken(ctx, tok.PlainToken, ""); !errors.Is(err, ErrInvalidLoginToken) {
		t.Errorf("second use: %v", err)
	}
}

// TestSingleUseLoginTokenConcurrent verifies on PostgreSQL that a
// single-use token presented concurrently signs in exactly once.
func TestSingleUseLoginTokenConcurrent(t *testing.T) {
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
		tok := issue(t, svc, pid, time.Now().Add(time.Minute), true)
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Go(func() {
				_, errs[i] = svc.VerifyLoginToken(ctx, tok.PlainToken, "")
			})
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrInvalidLoginToken):
				t.Fatalf("VerifyLoginToken: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("successful uses = %d, want 1", ok)
		}
	}
}
