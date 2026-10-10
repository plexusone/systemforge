package managedprincipal

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

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/internal/pgtest"
)

func TestClaim(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, rec := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	stranger := addHuman(t, db, "stranger@example.com", true)
	learner, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := svc.IssueClaim(ctx, stranger, learner); !errors.Is(err, ErrForbidden) {
		t.Errorf("IssueClaim by stranger = %v, want ErrForbidden", err)
	}
	claim, err := svc.IssueClaim(ctx, teacher, learner)
	if err != nil {
		t.Fatalf("IssueClaim: %v", err)
	}
	if !strings.HasPrefix(claim.Code, ClaimCodePrefix) || len(claim.Code) != 36 {
		t.Errorf("code %q", claim.Code)
	}
	if want := svc.now().Add(DefaultClaimTTL); claim.ExpiresAt.Sub(want).Abs() > time.Minute {
		t.Errorf("expires %v, want about %v", claim.ExpiresAt, want)
	}
	// The claim code is not a login token.
	if _, err := svc.creds.VerifyLoginToken(ctx, claim.Code, ""); err == nil {
		t.Error("claim code signs in")
	}

	// The managed principal itself and another managed principal cannot
	// redeem; a failed redemption does not spend the claim.
	other, err := svc.Create(ctx, CreateInput{DisplayName: "Other", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	for _, who := range []uuid.UUID{learner, other} {
		if _, err := svc.RedeemClaim(ctx, claim.Code, who); !errors.Is(err, ErrInvalidManager) {
			t.Errorf("RedeemClaim by managed = %v, want ErrInvalidManager", err)
		}
	}

	// Typed by hand: lowercase with grouping.
	typed := strings.ToLower(claim.Code[:10]) + " - " + claim.Code[10:]
	got, err := svc.RedeemClaim(ctx, typed, parent)
	if err != nil || got != learner {
		t.Fatalf("RedeemClaim = %v, %v", got, err)
	}
	roles, err := svc.ManagerRoles(ctx, parent, learner)
	if err != nil || len(roles) != 1 || roles[0] != RoleGuardian {
		t.Errorf("parent roles = %v, %v", roles, err)
	}
	if _, err := svc.RedeemClaim(ctx, claim.Code, stranger); !errors.Is(err, ErrInvalidClaim) {
		t.Errorf("second redemption = %v, want ErrInvalidClaim", err)
	}

	// Expired, unknown, and forged codes.
	expiring, err := svc.IssueClaim(ctx, parent, learner)
	if err != nil {
		t.Fatalf("IssueClaim by guardian: %v", err)
	}
	svc.now = func() time.Time { return time.Now().Add(DefaultClaimTTL + time.Minute) }
	for name, code := range map[string]string{
		"expired": expiring.Code,
		"unknown": ClaimCodePrefix + strings.Repeat("A", 32),
		"forged":  expiring.Code[:20] + strings.Repeat("Z", 16),
		"garbage": "hello",
	} {
		if _, err := svc.RedeemClaim(ctx, code, stranger); !errors.Is(err, ErrInvalidClaim) {
			t.Errorf("%s: %v, want ErrInvalidClaim", name, err)
		}
	}

	var issued, redeemed int
	for _, e := range rec.events {
		switch e.EventType {
		case EventClaimIssued:
			issued++
		case EventClaimRedeemed:
			redeemed++
		}
	}
	if issued != 2 || redeemed != 1 {
		t.Errorf("audit issued=%d redeemed=%d", issued, redeemed)
	}
}

func TestAttachVerifiedEmail(t *testing.T) {
	ctx := context.Background()
	db := openSQLite(t)
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, "teacher@example.com", true)
	parent := addHuman(t, db, "parent@example.com", true)
	learner, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client,
		Managers: []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Now()

	if err := svc.AttachVerifiedEmail(ctx, teacher, learner, "kid@example.com", now); !errors.Is(err, ErrForbidden) {
		t.Errorf("educator attach = %v, want ErrForbidden", err)
	}
	if err := svc.AttachVerifiedEmail(ctx, parent, learner, " ", now); !errors.Is(err, ErrEmailRequired) {
		t.Errorf("empty = %v", err)
	}
	if err := svc.AttachVerifiedEmail(ctx, parent, learner, "Teacher@Example.com", now); !errors.Is(err, ErrEmailInUse) {
		t.Errorf("taken = %v, want ErrEmailInUse", err)
	}
	if err := svc.AttachVerifiedEmail(ctx, parent, learner, "kid@example.com", now); err != nil {
		t.Fatalf("AttachVerifiedEmail: %v", err)
	}

	p, err := db.Principal.Get(ctx, learner)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	// Attaching an email changes nothing about management (ADR-009).
	if p.Identifier != "kid@example.com" || p.Capabilities["can_manage_profile"] {
		t.Errorf("principal after attach = %+v", p)
	}
	if managed, err := svc.IsManaged(ctx, learner); err != nil || !managed {
		t.Errorf("IsManaged after attach = %v, %v; want true", managed, err)
	}
	if err := svc.AttachVerifiedEmail(ctx, parent, learner, "again@example.com", now); !errors.Is(err, ErrHasEmail) {
		t.Errorf("second attach = %v, want ErrHasEmail", err)
	}
	// Relationships persist, and now the last may be removed.
	for _, m := range []ManagerInput{{teacher, RoleEducator}, {parent, RoleGuardian}} {
		if err := svc.RemoveManager(ctx, learner, m, parent); err != nil {
			t.Errorf("RemoveManager after attach: %v", err)
		}
	}
	if managed, err := svc.IsManaged(ctx, learner); err != nil || managed {
		t.Errorf("IsManaged after removal = %v, %v; want false", managed, err)
	}
	if err := svc.AttachVerifiedEmail(ctx, parent, learner, "again@example.com", now); !errors.Is(err, ErrNotManaged) {
		t.Errorf("attach after management ended = %v, want ErrNotManaged", err)
	}
}

// TestConcurrentRedeem verifies on PostgreSQL that a claim makes exactly
// one guardian when redeemed concurrently.
func TestConcurrentRedeem(t *testing.T) {
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
	svc, _ := newService(t, db)
	teacher := addHuman(t, db, uuid.NewString()+"@example.com", true)
	learner, err := svc.Create(ctx, CreateInput{DisplayName: "Learner", ClientID: client, Managers: []ManagerInput{{teacher, RoleEducator}}})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	for range 5 {
		claim, err := svc.IssueClaim(ctx, teacher, learner)
		if err != nil {
			t.Fatalf("IssueClaim: %v", err)
		}
		const n = 6
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			claimant := addHuman(t, db, uuid.NewString()+"@example.com", true)
			wg.Go(func() { _, errs[i] = svc.RedeemClaim(ctx, claim.Code, claimant) })
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case !errors.Is(err, ErrInvalidClaim):
				t.Fatalf("RedeemClaim: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("successful redemptions = %d, want 1", ok)
		}
	}
}
