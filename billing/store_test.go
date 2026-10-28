package billing

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	"github.com/plexusone/payforge"
	"github.com/plexusone/payforge/payforgetest"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/internal/pgtest"

	_ "github.com/mattn/go-sqlite3"
)

// backend opens a migrated, empty database.
type backend struct {
	name string
	open func(t *testing.T) *ent.Client
}

var backends = []backend{{"sqlite", openSQLite}, {"postgres", openPostgres}}

// openDB returns an empty in-memory SQLite database with the schema.
func openDB(t *testing.T) *ent.Client { return openSQLite(t) }

// openSQLite returns a migrated client on a private in-memory database.
// One connection serializes access, as SQLite requires.
func openSQLite(t *testing.T) *ent.Client {
	t.Helper()
	db, err := sql.Open("sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("closing sqlite: %v", err)
		}
	})
	return migrate(t, entsql.OpenDB(dialect.SQLite, db))
}

// openPostgres returns a migrated client on a scratch PostgreSQL database,
// skipping when SF_TEST_PG_DSN is unset.
func openPostgres(t *testing.T) *ent.Client {
	t.Helper()
	return migrate(t, entsql.OpenDB(dialect.Postgres, pgtest.Open(t)))
}

func migrate(t *testing.T, drv *entsql.Driver) *ent.Client {
	t.Helper()
	client := ent.NewClient(ent.Driver(drv))
	if err := client.Schema.Create(context.Background()); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return client
}

func forEachBackend(t *testing.T, fn func(t *testing.T, open func(t *testing.T) *ent.Client)) {
	t.Helper()
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) { fn(t, b.open) })
	}
}

// linker returns the link function the conformance suite uses, failing the
// test on an error.
func linker(t *testing.T, s *Store) func(customerID, subject string) {
	return func(customerID, subject string) {
		org, err := uuid.Parse(subject)
		if err != nil {
			// The suite names subjects freely; give each a stable UUID.
			org = uuid.NewSHA1(uuid.NameSpaceOID, []byte(subject))
		}
		if err := s.LinkCustomer(context.Background(), customerID, org); err != nil {
			t.Fatalf("LinkCustomer: %v", err)
		}
	}
}

func TestStoreConforms(t *testing.T) {
	forEachBackend(t, func(t *testing.T, open func(t *testing.T) *ent.Client) {
		payforgetest.Store(t, func(t *testing.T) (payforge.Store, func(customerID, subject string)) {
			s := NewStore(open(t))
			return subjectNames{s}, linker(t, s)
		})
	})
}

// subjectNames maps the UUIDs the store returns back to the names the
// conformance suite linked, so it can compare them.
type subjectNames struct{ *Store }

func (s subjectNames) SubjectForCustomer(ctx context.Context, customerID string) (string, error) {
	got, err := s.Store.SubjectForCustomer(ctx, customerID)
	if err != nil {
		return "", err
	}
	for _, name := range []string{"org-1", "org-2"} {
		if uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String() == got {
			return name, nil
		}
	}
	return got, nil
}

func TestLinkCustomer(t *testing.T) {
	forEachBackend(t, func(t *testing.T, open func(t *testing.T) *ent.Client) { testLinkCustomer(t, NewStore(open(t))) })
}

func testLinkCustomer(t *testing.T, s *Store) {
	ctx := context.Background()
	orgA, orgB := uuid.New(), uuid.New()

	if err := s.LinkCustomer(ctx, "cus_1", orgA); err != nil {
		t.Fatal(err)
	}
	if err := s.LinkCustomer(ctx, "cus_1", orgA); err != nil {
		t.Fatalf("linking again: %v", err)
	}
	if err := s.LinkCustomer(ctx, "cus_1", orgB); !errors.Is(err, ErrCustomerConflict) {
		t.Fatalf("another organization's customer: %v, want ErrCustomerConflict", err)
	}
	// A new customer for the organization replaces the old one.
	if err := s.LinkCustomer(ctx, "cus_2", orgA); err != nil {
		t.Fatal(err)
	}
	got, err := s.CustomerForOrganization(ctx, orgA)
	if err != nil || got != "cus_2" {
		t.Fatalf("CustomerForOrganization = %q, %v", got, err)
	}
	if _, err := s.SubjectForCustomer(ctx, "cus_1"); !errors.Is(err, payforge.ErrNotFound) {
		t.Fatalf("old customer: %v, want ErrNotFound", err)
	}
	if _, err := s.CustomerForOrganization(ctx, orgB); !errors.Is(err, payforge.ErrNotFound) {
		t.Fatalf("organization without a customer: %v", err)
	}
	if err := s.LinkCustomer(ctx, "", orgB); err == nil {
		t.Fatal("an empty customer was linked")
	}
}

func TestPruneEvents(t *testing.T) {
	ctx := context.Background()
	s := NewStore(openDB(t))
	if err := s.MarkSeen(ctx, "evt_old"); err != nil {
		t.Fatal(err)
	}
	n, err := s.PruneEvents(ctx, time.Now().Add(-time.Hour))
	if err != nil || n != 0 {
		t.Fatalf("pruning nothing: %d, %v", n, err)
	}
	n, err = s.PruneEvents(ctx, time.Now().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pruning: %d, %v", n, err)
	}
	if seen, err := s.Seen(ctx, "evt_old"); err != nil || seen {
		t.Fatalf("pruned event still seen: %v, %v", seen, err)
	}
}
