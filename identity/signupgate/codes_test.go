package signupgate

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/ent/signupcode"
	"github.com/plexusone/systemforge/identity/systemauth"
)

func newClient(t *testing.T) *ent.Client {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	return db
}

func newCodeStore(t *testing.T) (*CodeStore, *ent.Client) {
	t.Helper()
	c := newClient(t)
	return NewCodeStore(c, MemberOptions{}), c
}

func operatorCode(t *testing.T, s *CodeStore, maxUses int) (Code, string) {
	t.Helper()
	c, code, err := s.CreateCode(t.Context(), CodeOptions{Kind: CodeOperator, Label: "launch", MaxUses: maxUses, CreatedByLabel: "ops"})
	if err != nil {
		t.Fatal(err)
	}
	return c, code
}

func TestNormalizeAndFormatCode(t *testing.T) {
	want := "0123ABCD1111WXYZ"
	for _, in := range []string{"0123-ABCD-1111-WXYZ", "0123abcd1111wxyz", " 0123 ABCD-iIlL wxyz", "O123-ABCD-1111-WXYZ"} {
		got, err := NormalizeCode(in)
		if err != nil || got != want {
			t.Errorf("NormalizeCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0123-ABCD-1111", "0123-ABCD-1111-WXYZ-0", "0123-ABCD-1111-WXYU", "0123_ABCD_1111_WXYZ"} {
		if _, err := NormalizeCode(bad); !errors.Is(err, ErrCodeInvalid) {
			t.Errorf("NormalizeCode(%q) accepted", bad)
		}
	}
	if got := FormatCode(want); got != "0123-ABCD-1111-WXYZ" {
		t.Errorf("FormatCode = %q", got)
	}
}

func TestGeneratedCodesAreDistinctAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		c, err := generateCode()
		if err != nil {
			t.Fatal(err)
		}
		if n, err := NormalizeCode(c); err != nil || n != c {
			t.Fatalf("generated %q does not normalize to itself: %q, %v", c, n, err)
		}
		if seen[c] {
			t.Fatalf("duplicate code %q", c)
		}
		seen[c] = true
	}
}

func TestCreateCodeStoresOnlyTheHash(t *testing.T) {
	s, client := newCodeStore(t)
	c, code, err := s.CreateCode(t.Context(), CodeOptions{Kind: CodeOperator, Label: "launch", Note: "for the meetup", MaxUses: 20})
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := NormalizeCode(code)
	if err != nil {
		t.Fatalf("returned code %q is not a code: %v", code, err)
	}
	if c.Hint != normalized[12:] || c.Kind != CodeOperator || c.MaxUses != 20 || c.Status(time.Now()) != CodeActive {
		t.Errorf("code = %+v", c)
	}
	row, err := client.SignupCode.Get(t.Context(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.CodeHash == normalized || strings.Contains(row.CodeHash, normalized) || row.CodeHash != hashCode(normalized) {
		t.Errorf("stored hash %q does not hide the code", row.CodeHash)
	}
	if got, err := s.Lookup(t.Context(), strings.ToLower(code)); err != nil || got.ID != c.ID {
		t.Errorf("Lookup = %+v, %v", got, err)
	}
	if _, err := s.Lookup(t.Context(), "0000-0000-0000-0000"); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("unknown code: %v", err)
	}
	for _, bad := range []CodeOptions{{Kind: CodeOperator}, {Kind: "other", MaxUses: 1}} {
		if _, _, err := s.CreateCode(t.Context(), bad); err == nil {
			t.Errorf("CreateCode(%+v) accepted", bad)
		}
	}
}

func TestReserveStopsAtTheLimitAndReleaseGivesBack(t *testing.T) {
	s, _ := newCodeStore(t)
	ctx := t.Context()
	c, code := operatorCode(t, s, 2)
	for i := range 2 {
		id, err := s.Reserve(ctx, code)
		if err != nil || id != c.ID {
			t.Fatalf("reserve %d = %s, %v", i, id, err)
		}
	}
	if _, err := s.Reserve(ctx, code); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("third reserve of a two-use code: %v", err)
	}
	if got, _ := s.GetCode(ctx, c.ID); got.Status(time.Now()) != CodeUsedUp {
		t.Errorf("status = %s, want used_up", got.Status(time.Now()))
	}
	if err := s.Release(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Reserve(ctx, code); err != nil {
		t.Errorf("a released use is not usable again: %v", err)
	}
}

func TestReserveRefusesExpiredAndRevoked(t *testing.T) {
	s, _ := newCodeStore(t)
	ctx := t.Context()
	now := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	s.now = func() time.Time { return now }
	expiry := now.Add(time.Hour)
	c, code, err := s.CreateCode(ctx, CodeOptions{Kind: CodeOperator, MaxUses: 5, ExpiresAt: &expiry})
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	if _, err := s.Reserve(ctx, code); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("expired code reserved: %v", err)
	}
	if got, _ := s.GetCode(ctx, c.ID); got.Status(now) != CodeExpired {
		t.Errorf("status = %s, want expired", got.Status(now))
	}

	c2, code2 := operatorCode(t, s, 5)
	if err := s.RevokeCode(ctx, c2.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeCode(ctx, c2.ID); err != nil {
		t.Errorf("revoking twice: %v", err)
	}
	if _, err := s.Reserve(ctx, code2); !errors.Is(err, ErrCodeInvalid) {
		t.Errorf("revoked code reserved: %v", err)
	}
	if err := s.RevokeCode(ctx, uuid.New()); !errors.Is(err, ErrCodeNotFound) {
		t.Errorf("revoking an unknown code: %v", err)
	}
}

func TestListCodesAndRedemptions(t *testing.T) {
	s, _ := newCodeStore(t)
	ctx := t.Context()
	member := uuid.New()
	op, opCode := operatorCode(t, s, 3)
	mc, mcCode, err := s.CreateCode(ctx, CodeOptions{Kind: CodeMember, MaxUses: 1, CreatedByPrincipal: &member})
	if err != nil {
		t.Fatal(err)
	}
	all, err := s.ListCodes(ctx, CodeFilter{})
	if err != nil || len(all) != 2 || all[0].ID != mc.ID {
		t.Fatalf("ListCodes = %+v, %v; want both, newest first", all, err)
	}
	if got, _ := s.ListCodes(ctx, CodeFilter{Kind: CodeMember}); len(got) != 1 || got[0].ID != mc.ID {
		t.Errorf("by kind = %+v", got)
	}
	if got, _ := s.ListCodes(ctx, CodeFilter{CreatedBy: &member}); len(got) != 1 {
		t.Errorf("by creator = %+v", got)
	}

	for _, r := range []struct {
		code  string
		email string
	}{{opCode, "ada@example.com"}, {mcCode, "Grace@Example.com"}} {
		id, err := s.Reserve(ctx, r.code)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Redeem(ctx, id, uuid.New(), r.email); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := s.ListCodes(ctx, CodeFilter{ActiveOnly: true}); len(got) != 1 || got[0].ID != op.ID {
		t.Errorf("active = %+v; the used member code should be gone", got)
	}
	reds, err := s.Redemptions(ctx, RedemptionFilter{})
	if err != nil || len(reds) != 2 {
		t.Fatalf("Redemptions = %+v, %v", reds, err)
	}
	byMember, _ := s.Redemptions(ctx, RedemptionFilter{CreatedBy: &member})
	if len(byMember) != 1 || byMember[0].Email != "grace@example.com" || byMember[0].CodeKind != CodeMember {
		t.Errorf("by member = %+v", byMember)
	}
	byLabel, _ := s.Redemptions(ctx, RedemptionFilter{Label: "launch"})
	if len(byLabel) != 1 || byLabel[0].CodeID != op.ID || byLabel[0].CodeCreatedByLabel != "ops" {
		t.Errorf("by label = %+v", byLabel)
	}
}

// TestReserveIsExactUnderConcurrency races many sign-ups for one code on a
// file database and checks that exactly its use limit is reserved.
func TestReserveIsExactUnderConcurrency(t *testing.T) {
	path := filepath.Join(t.TempDir(), "codes.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?_fk=1&_busy_timeout=10000&_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	client := ent.NewClient(ent.Driver(entsql.OpenDB("sqlite3", db)))
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("closing ent client: %v", err)
		}
	})
	if err := client.Schema.Create(t.Context()); err != nil {
		t.Fatal(err)
	}
	s := NewCodeStore(client, MemberOptions{})
	c, code := operatorCode(t, s, 5)

	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 40 {
		wg.Go(func() {
			_, err := s.Reserve(t.Context(), code)
			switch {
			case err == nil:
				mu.Lock()
				won++
				mu.Unlock()
			case !errors.Is(err, ErrCodeInvalid):
				t.Errorf("reserve: %v", err)
			}
		})
	}
	wg.Wait()
	if won != 5 {
		t.Errorf("%d sign-ups reserved a five-use code", won)
	}
	row, err := client.SignupCode.Query().Where(signupcode.IDEQ(c.ID)).Only(t.Context())
	if err != nil || row.UseCount != 5 {
		t.Errorf("use_count = %d, %v; want 5", row.UseCount, err)
	}
}

func TestGateAdmitsWithACode(t *testing.T) {
	client := newClient(t)
	invites, codes := NewStore(client), NewCodeStore(client, MemberOptions{})
	g := NewGate(invites, WithCodes(codes))
	ctx := t.Context()
	c, code := operatorCode(t, codes, 1)
	login := systemauth.ExternalLogin{Provider: "github", Subject: "7", Email: "ada@example.com", EmailVerified: true}

	if err := g.AllowSignup(ctx, login); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Fatalf("no invite, no code: %v", err)
	}
	withCode := systemauth.WithSignupCode(ctx, code)
	if err := g.AllowSignup(withCode, login); err != nil {
		t.Fatalf("code holder refused: %v", err)
	}
	pid := uuid.New()
	if err := g.SignedUp(withCode, login, pid); err != nil {
		t.Fatal(err)
	}
	reds, err := codes.Redemptions(ctx, RedemptionFilter{CodeID: &c.ID})
	if err != nil || len(reds) != 1 || reds[0].PrincipalID != pid {
		t.Fatalf("redemptions = %+v, %v", reds, err)
	}
	other := login
	other.Subject, other.Email = "8", "grace@example.com"
	if err := g.AllowSignup(withCode, other); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("a used-up code admits a second sign-up: %v", err)
	}
	unverified := other
	unverified.EmailVerified = false
	c2, code2 := operatorCode(t, codes, 1)
	if err := g.AllowSignup(systemauth.WithSignupCode(ctx, code2), unverified); !errors.Is(err, systemauth.ErrSignupNotInvited) {
		t.Errorf("unverified email admitted by a code: %v", err)
	}
	if got, _ := codes.GetCode(ctx, c2.ID); got.UseCount != 0 {
		t.Errorf("an unverified login reserved a use: %d", got.UseCount)
	}
}

func TestGatePrefersTheEmailInviteAndReleasesOnAbort(t *testing.T) {
	client := newClient(t)
	invites, codes := NewStore(client), NewCodeStore(client, MemberOptions{})
	g := NewGate(invites, WithCodes(codes))
	ctx := t.Context()
	c, code := operatorCode(t, codes, 1)
	if _, err := invites.Add(ctx, "ada@example.com", AddOptions{}); err != nil {
		t.Fatal(err)
	}
	ada := systemauth.ExternalLogin{Provider: "google", Subject: "a", Email: "ada@example.com", EmailVerified: true}
	withCode := systemauth.WithSignupCode(ctx, code)
	if err := g.AllowSignup(withCode, ada); err != nil {
		t.Fatal(err)
	}
	if err := g.SignedUp(withCode, ada, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if got, _ := codes.GetCode(ctx, c.ID); got.UseCount != 0 {
		t.Errorf("an invited address used up the code: use_count %d", got.UseCount)
	}
	if ok, _ := invites.Allowed(ctx, "ada@example.com"); ok {
		t.Error("the email invite was not redeemed")
	}

	grace := systemauth.ExternalLogin{Provider: "google", Subject: "g", Email: "grace@example.com", EmailVerified: true}
	if err := g.AllowSignup(withCode, grace); err != nil {
		t.Fatal(err)
	}
	g.SignupAborted(withCode, grace)
	if got, _ := codes.GetCode(ctx, c.ID); got.UseCount != 0 {
		t.Errorf("an aborted sign-up kept its use: use_count %d", got.UseCount)
	}
	if err := g.AllowSignup(withCode, grace); err != nil {
		t.Errorf("retrying after an abort: %v", err)
	}
}
