package signup

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/organization"
)

func TestSlugForLogin(t *testing.T) {
	tests := []struct {
		name, provider, login, email, want string
	}{
		{"github username", "github", "Octo-Cat", "octo@example.com", "octo-cat"},
		{"github falls back to email", "github", "", "octo@example.com", "octo"},
		{"google local part", "google", "ignored", "Jane.Doe@gmail.com", "janedoe"},
		{"google falls back to login", "google", "janed", "", "janed"},
		{"other provider prefers login", "gitlab", "kim", "lee@example.com", "kim"},
		{"short padded", "github", "ab", "", "ab-org"},
		{"leading digit", "github", "42cats", "", "u-42cats"},
		{"nothing usable", "github", "", "", "user"},
		{"symbols only", "google", "", "+++@example.com", "user"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SlugForLogin(tt.provider, tt.login, tt.email)
			if got != tt.want {
				t.Errorf("SlugForLogin = %q, want %q", got, tt.want)
			}
			if !organization.IsValidSlug(got) {
				t.Errorf("%q is not a valid slug", got)
			}
		})
	}
	long := SlugForLogin("github", strings.Repeat("a", 80), "")
	if len(long) != 63 || !organization.IsValidSlug(long) {
		t.Errorf("long slug = %q (%d)", long, len(long))
	}
}

func TestCreatePersonalOrgInTx(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	newOwner := func(email string) uuid.UUID {
		p, err := f.db.Principal.Create().SetType("human").SetIdentifier(email).SetDisplayName(email).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p.ID
	}

	create := func(owner uuid.UUID, slug string) *PersonalOrg {
		tx, err := f.db.Tx(ctx)
		if err != nil {
			t.Fatal(err)
		}
		po, err := CreatePersonalOrgInTx(ctx, tx, PersonalOrgParams{OwnerID: owner, Name: "N", Slug: slug})
		if err != nil {
			t.Fatalf("CreatePersonalOrgInTx: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return po
	}

	first := create(newOwner("a@example.com"), "kim")
	second := create(newOwner("b@example.com"), "kim")
	third := create(newOwner("c@example.com"), "kim")
	if first.Organization.Slug != "kim" || second.Organization.Slug != "kim-1" || third.Organization.Slug != "kim-2" {
		t.Errorf("slugs = %q %q %q", first.Organization.Slug, second.Organization.Slug, third.Organization.Slug)
	}
	if first.Organization.OrgType.String() != "personal" || first.Membership.Role != organization.RoleOwner || !first.Membership.Active {
		t.Errorf("org/membership = %+v / %+v", first.Organization, first.Membership)
	}

	// A suffix never pushes the slug past 63 characters.
	long := strings.Repeat("a", 63)
	l1 := create(newOwner("d@example.com"), long)
	l2 := create(newOwner("e@example.com"), long)
	if len(l1.Organization.Slug) != 63 || len(l2.Organization.Slug) > 63 || !organization.IsValidSlug(l2.Organization.Slug) {
		t.Errorf("long slugs = %q, %q", l1.Organization.Slug, l2.Organization.Slug)
	}
}

func TestEnsurePersonalOrgInTxIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	p, err := f.db.Principal.Create().SetType("human").SetIdentifier("x@example.com").SetDisplayName("X").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ensure := func() (*PersonalOrg, bool) {
		tx, err := f.db.Tx(ctx)
		if err != nil {
			t.Fatal(err)
		}
		po, created, err := EnsurePersonalOrgInTx(ctx, tx, PersonalOrgParams{OwnerID: p.ID, Name: "X", Slug: "xavier"})
		if err != nil {
			t.Fatalf("EnsurePersonalOrgInTx: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return po, created
	}
	a, created := ensure()
	if !created {
		t.Fatal("first call did not create")
	}
	b, created := ensure()
	if created || b.Organization.ID != a.Organization.ID {
		t.Fatalf("second call created=%v id=%v want %v", created, b.Organization.ID, a.Organization.ID)
	}
	if n := f.db.Organization.Query().CountX(ctx); n != 1 {
		t.Errorf("organizations = %d, want 1", n)
	}
}

func TestSlugForManaged(t *testing.T) {
	if got := SlugForManaged("Kim's Kid"); got != "kims-kid" {
		t.Errorf("entered = %q", got)
	}
	re := regexp.MustCompile(`^[a-z]+-[a-z]+-[0-9]{2}$`)
	for range 50 {
		got := SlugForManaged("")
		if !re.MatchString(got) || !organization.IsValidSlug(got) {
			t.Fatalf("generated slug %q has the wrong shape", got)
		}
	}
}

func TestCreatePersonalOrgInTxSkipsReservedSlugs(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	create := func(email, slug string, reserved ...string) string {
		p, err := f.db.Principal.Create().SetType("human").SetIdentifier(email).SetDisplayName(email).Save(ctx)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := f.db.Tx(ctx)
		if err != nil {
			t.Fatal(err)
		}
		po, err := CreatePersonalOrgInTx(ctx, tx, PersonalOrgParams{OwnerID: p.ID, Name: "N", Slug: slug, ReservedSlugs: reserved})
		if err != nil {
			t.Fatalf("CreatePersonalOrgInTx: %v", err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		return po.Organization.Slug
	}
	if got := create("a@example.com", "admin"); got != "admin-1" {
		t.Errorf("built-in reserved: %q, want admin-1", got)
	}
	if got := create("b@example.com", "notes", "Notes", "notes-1"); got != "notes-2" {
		t.Errorf("configured reserved: %q, want notes-2", got)
	}
}
