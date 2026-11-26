package systemauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plexusone/systemforge/identity/ent"
	entorg "github.com/plexusone/systemforge/identity/ent/organization"
)

func countsOf(t *testing.T, db *ent.Client) (principals, humans, identities, orgs, memberships int) {
	t.Helper()
	ctx := context.Background()
	return db.Principal.Query().CountX(ctx), db.Human.Query().CountX(ctx),
		db.ExternalIdentity.Query().CountX(ctx), db.Organization.Query().CountX(ctx),
		db.PrincipalMembership.Query().CountX(ctx)
}

func assertCounts(t *testing.T, db *ent.Client, p, h, i, o, m int) {
	t.Helper()
	gp, gh, gi, go_, gm := countsOf(t, db)
	if gp != p || gh != h || gi != i || go_ != o || gm != m {
		t.Errorf("principals/humans/identities/orgs/memberships = %d/%d/%d/%d/%d, want %d/%d/%d/%d/%d",
			gp, gh, gi, go_, gm, p, h, i, o, m)
	}
}

func TestSocialSignupFirstLoginCreatesPersonalOrg(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	now := time.Now()

	login := ExternalLogin{Provider: "github", Subject: "100", Email: "octo@example.com", EmailVerified: true, Name: "Octo Cat", Username: "octocat", AvatarURL: "https://img/octo"}
	p, err := ResolveExternalLogin(ctx, dir, login, now)
	if err != nil {
		t.Fatalf("first login: %v", err)
	}
	assertCounts(t, db, 1, 1, 1, 1, 1)

	org := db.Organization.Query().OnlyX(ctx)
	if org.Slug != "octocat" || org.OrgType != entorg.OrgTypePersonal || org.Name != "Octo Cat" ||
		org.OwnerPrincipalID == nil || *org.OwnerPrincipalID != p.ID || !org.Active {
		t.Errorf("organization = %+v", org)
	}
	if org.LogoURL == nil || *org.LogoURL != "https://img/octo" {
		t.Errorf("logo = %v", org.LogoURL)
	}
	m := db.PrincipalMembership.Query().OnlyX(ctx)
	if m.PrincipalID != p.ID || m.OrganizationID != org.ID || m.Role != "owner" || !m.Active {
		t.Errorf("membership = %+v", m)
	}

	// Second login: same principal, nothing new.
	p2, err := ResolveExternalLogin(ctx, dir, login, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if p2.ID != p.ID {
		t.Fatalf("second login principal %v, want %v", p2.ID, p.ID)
	}
	assertCounts(t, db, 1, 1, 1, 1, 1)
}

func TestSocialSignupNamesAreNeverFromTheEmail(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	now := time.Now()

	// Two logins whose addresses would have made the same handle. Whatever
	// they are named, nothing comes from the address.
	logins := []ExternalLogin{
		{Provider: "google", Subject: "g1", Email: "jane@gmail.com", EmailVerified: true, Name: "Jane Doe"},
		{Provider: "google", Subject: "g2", Email: "jane@example.org", EmailVerified: true, Name: "Jane Roe", OrganizationName: "Roe Studio"},
	}
	for _, l := range logins {
		if _, err := ResolveExternalLogin(ctx, dir, l, now); err != nil {
			t.Fatalf("login %s: %v", l.Subject, err)
		}
	}
	names := map[string]bool{}
	slugs := map[string]bool{}
	for _, o := range db.Organization.Query().AllX(ctx) {
		names[o.Name] = true
		slugs[o.Slug] = true
		if strings.Contains(o.Slug, "jane") || strings.Contains(o.Slug, "example") || strings.Contains(o.Slug, "gmail") {
			t.Errorf("slug %q is made from the address", o.Slug)
		}
	}
	if !names["Jane Doe"] || !names["Roe Studio"] || len(names) != 2 {
		t.Errorf("organization names = %v, want the name given and the workspace name given", names)
	}
	if len(slugs) != 2 {
		t.Errorf("slugs = %v, want two distinct generated slugs", slugs)
	}
	for _, p := range db.Principal.Query().AllX(ctx) {
		if strings.Contains(p.DisplayName, "@") {
			t.Errorf("display name %q is an email address", p.DisplayName)
		}
	}
}

func TestSocialSignupUsesTheHandleForTheSlug(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	if _, err := ResolveExternalLogin(ctx, dir, ExternalLogin{
		Provider: "github", Subject: "7", Email: "octo@example.com", EmailVerified: true, EmailAuthoritative: true,
		Name: "Octo Cat", Username: "octocat",
	}, time.Now()); err != nil {
		t.Fatalf("login: %v", err)
	}
	orgs := db.Organization.Query().AllX(ctx)
	if len(orgs) != 1 || orgs[0].Slug != "octocat" || orgs[0].Name != "Octo Cat" {
		t.Fatalf("organizations = %+v, want one named Octo Cat with the handle as its slug", orgs)
	}
}

func TestSocialSignupSameEmailOtherProviderLinks(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	now := time.Now()

	first, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: true, Username: "kim"}, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "google", Subject: "g-1", Email: "Kim@example.com", EmailVerified: true, EmailAuthoritative: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatal("second provider created a new principal instead of linking")
	}
	assertCounts(t, db, 1, 1, 2, 1, 1)
}

func TestSocialSignupUnverifiedEmailCreatesNothing(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	_, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: false, Username: "kim"}, time.Now())
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("err = %v, want ErrEmailNotVerified", err)
	}
	assertCounts(t, db, 0, 0, 0, 0, 0)
}

func TestSocialSignupOrganizationFailureRollsBackPrincipal(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	boom := errors.New("organization store unavailable")
	db.Organization.Use(func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			if m.Op().Is(ent.OpCreate) {
				return nil, boom
			}
			return next.Mutate(ctx, m)
		})
	})
	dir := NewEntPrincipalDirectory(db)

	_, err := ResolveExternalLogin(ctx, dir, ExternalLogin{Provider: "github", Subject: "1", Email: "kim@example.com", EmailVerified: true, Username: "kim"}, time.Now())
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the organization failure", err)
	}
	assertCounts(t, db, 0, 0, 0, 0, 0)
}

func TestSocialSignupConcurrentFirstLogins(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	login := ExternalLogin{Provider: "github", Subject: "7", Email: "race@example.com", EmailVerified: true, Username: "racer"}

	const n = 8
	ids := make(chan string, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := ResolveExternalLogin(ctx, dir, login, time.Now())
			if err != nil {
				errs <- err
				return
			}
			ids <- p.ID.String()
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		// SQLite serializes writers with lock errors under contention; a
		// resolver-level conflict would be a real failure.
		if errors.Is(err, ErrExternalIdentityExists) || errors.Is(err, ErrEmailConflict) {
			t.Errorf("unresolved conflict: %v", err)
		}
	}
	seen := map[string]bool{}
	for id := range ids {
		seen[id] = true
	}
	if len(seen) != 1 {
		t.Errorf("distinct principals returned = %d, want 1", len(seen))
	}
	assertCounts(t, db, 1, 1, 1, 1, 1)
}

func TestSocialLoginBackfillsPersonalOrg(t *testing.T) {
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	now := time.Now()

	// A principal created before signup-on-first-login: principal, human and
	// external identity, but no organization.
	existing := seedHuman(t, db, "old@example.com", true)
	login := ExternalLogin{Provider: "github", Subject: "55", Email: "old@example.com", EmailVerified: true, Username: "oldtimer", Name: "Old Timer"}
	if err := dir.LinkExternalIdentity(ctx, existing, login); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, db, 1, 1, 1, 0, 0)

	p, err := ResolveExternalLogin(ctx, dir, login, now)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if p.ID != existing {
		t.Fatal("login resolved to a different principal")
	}
	assertCounts(t, db, 1, 1, 1, 1, 1)
	org := db.Organization.Query().OnlyX(ctx)
	if org.Slug != "oldtimer" || org.OwnerPrincipalID == nil || *org.OwnerPrincipalID != existing {
		t.Errorf("backfilled organization = %+v", org)
	}

	// Idempotent: a further login adds nothing.
	if _, err := ResolveExternalLogin(ctx, dir, login, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	assertCounts(t, db, 1, 1, 1, 1, 1)
}

// TestManagedPrincipalPersonalOrgSlugIgnoresEmail verifies that a managed
// principal with an email gets a generated slug and its managers' name,
// never a handle derived from its address or provider username (ADR-009).
func TestManagedPrincipalPersonalOrgSlugIgnoresEmail(t *testing.T) {
	// The fixture uses a generic name; a real first name could be a word the
	// slug generator draws (it has a "robin"), and the leak check would fail
	// at random.
	ctx := context.Background()
	db := openTestEnt(t)
	dir := NewEntPrincipalDirectory(db)
	now := time.Now()

	student := seedHuman(t, db, "example.user@school.example", true)
	guardian := seedHuman(t, db, "guardian@example.com", true)
	if err := db.ManagerRelationship.Create().SetManagedPrincipalID(student).SetManagerPrincipalID(guardian).
		SetRole("guardian").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Principal.UpdateOneID(student).SetDisplayName("Pat").Exec(ctx); err != nil {
		t.Fatal(err)
	}
	login := ExternalLogin{Provider: "google", Subject: "g-student", Email: "example.user@school.example", EmailVerified: true, Username: "exampleuser", Name: "Example User"}
	if err := dir.LinkExternalIdentity(ctx, student, login); err != nil {
		t.Fatal(err)
	}

	p, err := ResolveExternalLogin(ctx, dir, login, now)
	if err != nil || p.ID != student || !p.Managed {
		t.Fatalf("login = %+v, %v", p, err)
	}
	org := db.Organization.Query().Where(entorg.OwnerPrincipalID(student)).OnlyX(ctx)
	for _, leak := range []string{"user", "school", "example"} {
		if strings.Contains(org.Slug, leak) {
			t.Errorf("slug %q reveals %q", org.Slug, leak)
		}
	}
	if org.Name != "Pat" {
		t.Errorf("organization name = %q, want the managers' display name", org.Name)
	}
	if org.LogoURL != nil {
		t.Errorf("logo = %v, want none", org.LogoURL)
	}
}
