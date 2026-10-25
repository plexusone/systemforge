package multiapp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/plexusone/systemforge/internal/pgtest"
)

// isPermissionDenied reports whether err is PostgreSQL's permission denied
// (SQLSTATE 42501).
func isPermissionDenied(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42501"
}

// pgFixture is a scratch database plus cluster-wide roles with unique
// names, dropped when the test ends.
type pgFixture struct {
	t      *testing.T
	dsn    string
	admin  *pgxpool.Pool
	suffix string
}

func newPGFixture(t *testing.T) *pgFixture {
	t.Helper()
	dsn := pgtest.DSN(t)
	admin, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	t.Cleanup(admin.Close)
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return &pgFixture{t: t, dsn: dsn, admin: admin, suffix: hex.EncodeToString(b)}
}

// name returns base with the fixture's unique suffix.
func (f *pgFixture) name(base string) string { return base + "_" + f.suffix }

// dropRolesLater drops roles when the test ends, after their pools close.
func (f *pgFixture) dropRolesLater(roles ...string) {
	f.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, r := range roles {
			if _, err := f.admin.Exec(ctx, "DROP OWNED BY "+quoteIdent(r)+" CASCADE"); err != nil {
				f.t.Errorf("drop owned by %s: %v", r, err)
			}
		}
		for _, r := range roles {
			if _, err := f.admin.Exec(ctx, "DROP ROLE IF EXISTS "+quoteIdent(r)); err != nil {
				f.t.Errorf("drop role %s: %v", r, err)
			}
		}
	})
}

// exec runs admin statements, failing the test on error.
func (f *pgFixture) exec(stmts ...string) {
	f.t.Helper()
	for _, s := range stmts {
		if _, err := f.admin.Exec(context.Background(), s); err != nil {
			f.t.Fatalf("%s: %v", s, err)
		}
	}
}

// loginURL is the scratch database's DSN with role as the user.
func (f *pgFixture) loginURL(role string) string {
	f.t.Helper()
	u, err := url.Parse(f.dsn)
	if err != nil {
		f.t.Fatal(err)
	}
	u.User = url.User(role)
	return u.String()
}

// loginPool connects as role.
func (f *pgFixture) loginPool(role string) *pgxpool.Pool {
	f.t.Helper()
	p, err := pgxpool.New(context.Background(), f.loginURL(role))
	if err != nil {
		f.t.Fatalf("pool for %s: %v", role, err)
	}
	f.t.Cleanup(p.Close)
	return p
}

// provisionedApps provisions an owner role and one login per slug, each
// with a notes table created by the owner and the shared sf_principals
// table readable. It returns the owner role and a pool per app login.
func (f *pgFixture) provisionedApps(slugs ...string) (string, []*pgxpool.Pool) {
	f.t.Helper()
	ctx := context.Background()
	owner := f.name("sfowner")
	roles := []string{owner}
	for _, s := range slugs {
		roles = append(roles, f.name("sfapp_"+s))
	}
	f.dropRolesLater(roles...)
	if err := ApplyOwnerRole(ctx, f.admin, owner, nil); err != nil {
		f.t.Fatalf("ApplyOwnerRole: %v", err)
	}
	f.exec(
		"CREATE TABLE IF NOT EXISTS public.sf_principals (id int)",
		"CREATE TABLE IF NOT EXISTS public.sf_credentials (secret text)",
	)
	ownerPool := f.loginPool(owner)
	var pools []*pgxpool.Pool
	for i, s := range slugs {
		p := RoleProvisioning{
			Schema:    SchemaFromAppSlug(s),
			Role:      roles[i+1],
			OwnerRole: owner,
		}
		if err := ApplyRoleProvisioning(ctx, f.admin, p, nil); err != nil {
			f.t.Fatalf("ApplyRoleProvisioning(%s): %v", s, err)
		}
		// The owner creates the app's tables after provisioning; default
		// privileges hand them to the app role.
		if _, err := ownerPool.Exec(ctx, "CREATE TABLE "+quoteQualified(p.Schema, "notes")+" (body text)"); err != nil {
			f.t.Fatalf("owner creates %s.notes: %v", p.Schema, err)
		}
		pools = append(pools, f.loginPool(p.Role))
	}
	return owner, pools
}
