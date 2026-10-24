package scimtoken_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rbac"
	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/scim/scimtoken"
	"github.com/plexusone/systemforge/internal/pgtest"
)

type backend struct {
	name string
	open func(t *testing.T) *ent.Client
}

var backends = []backend{{"sqlite", openSQLite}, {"postgres", openPostgres}}

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

func forEachBackend(t *testing.T, fn func(t *testing.T, client *ent.Client)) {
	t.Helper()
	for _, b := range backends {
		t.Run(b.name, func(t *testing.T) { fn(t, b.open(t)) })
	}
}

// fixture is two tenant organizations and principals with roles in them.
type fixture struct {
	client       *ent.Client
	orgA, orgB   uuid.UUID
	ownerA       uuid.UUID // owner of A
	adminA       uuid.UUID // admin of A
	memberA      uuid.UUID // member of A
	ownerB       uuid.UUID // owner of B
	platform     uuid.UUID // platform administrator, no membership
	auditEvents  *audit.MemoryStore
	authorizer   authz.Authorizer
	clockMu      sync.Mutex
	clockCurrent time.Time
}

func newFixture(t *testing.T, client *ent.Client) *fixture {
	t.Helper()
	ctx := context.Background()
	a, err := client.Organization.Create().SetName("Acme").SetSlug("acme").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, err := client.Organization.Create().SetName("Beta").SetSlug("beta").Save(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{
		client: client, orgA: a.ID, orgB: b.ID,
		ownerA: uuid.New(), adminA: uuid.New(), memberA: uuid.New(), ownerB: uuid.New(), platform: uuid.New(),
		auditEvents:  audit.NewMemoryStore(1000),
		clockCurrent: time.Now().UTC().Truncate(time.Second),
	}
	roles := map[[2]uuid.UUID]string{
		{f.ownerA, f.orgA}:  "owner",
		{f.adminA, f.orgA}:  "admin",
		{f.memberA, f.orgA}: "member",
		{f.ownerB, f.orgB}:  "owner",
	}
	f.authorizer = rbac.New(
		rbac.WithRoleGetter(func(_ context.Context, principalID, orgID uuid.UUID) (string, error) {
			return roles[[2]uuid.UUID{principalID, orgID}], nil
		}),
		rbac.WithPlatformAdminChecker(func(_ context.Context, principalID uuid.UUID) (bool, error) {
			return principalID == f.platform, nil
		}),
	)
	return f
}

func (f *fixture) now() time.Time {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	return f.clockCurrent
}

func (f *fixture) advance(d time.Duration) {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	f.clockCurrent = f.clockCurrent.Add(d)
}

type emitter struct{ store *audit.MemoryStore }

func (e emitter) Emit(ctx context.Context, ev *audit.Event) error {
	_, err := e.store.Record(ctx, ev)
	return err
}

func (f *fixture) service(opts ...scimtoken.Option) *scimtoken.Service {
	base := []scimtoken.Option{
		scimtoken.WithAuthorizer(f.authorizer),
		scimtoken.WithAuditEmitter(emitter{f.auditEvents}),
		scimtoken.WithClock(f.now),
	}
	return scimtoken.New(f.client, append(base, opts...)...)
}

func (f *fixture) events(t *testing.T, eventType string) []*audit.Event {
	t.Helper()
	all, err := f.auditEvents.GetBySequence(context.Background(), 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	var out []*audit.Event
	for _, e := range all {
		if e.EventType == eventType {
			out = append(out, e)
		}
	}
	return out
}

func mustAuth(t *testing.T, s *scimtoken.Service, token string, org uuid.UUID) *scimtoken.Token {
	t.Helper()
	got, err := s.Authenticate(context.Background(), token)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if got.OrganizationID != org {
		t.Fatalf("Authenticate: organization %s, want %s", got.OrganizationID, org)
	}
	return got
}

func refused(t *testing.T, s *scimtoken.Service, token, what string) {
	t.Helper()
	if _, err := s.Authenticate(context.Background(), token); !errors.Is(err, scimtoken.ErrInvalidToken) {
		t.Fatalf("%s: Authenticate error %v, want ErrInvalidToken", what, err)
	}
}

func TestRotationKeepsPreviousAndRevokesOlder(t *testing.T) {
	forEachBackend(t, func(t *testing.T, client *ent.Client) {
		f := newFixture(t, client)
		s := f.service()
		ctx := context.Background()

		t1, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{Description: "idp"})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		if !strings.HasPrefix(t1.Token, scimtoken.Prefix) || len(t1.Token) != scimtoken.Length {
			t.Fatalf("issued token does not have the documented format (length %d)", len(t1.Token))
		}
		if t1.Metadata.Prefix != t1.Token[:scimtoken.DisplayLength] || t1.Metadata.Generation != 1 {
			t.Fatalf("metadata: %+v", t1.Metadata)
		}
		mustAuth(t, s, t1.Token, f.orgA)

		if _, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{}); !errors.Is(err, scimtoken.ErrTokenExists) {
			t.Fatalf("second Issue: %v, want ErrTokenExists", err)
		}

		// Rotate: N=t2, N-1=t1 both valid.
		t2, err := s.Rotate(ctx, f.adminA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if len(t2.Revoked) != 0 {
			t.Fatalf("first rotation revoked %v, want none", t2.Revoked)
		}
		if got := mustAuth(t, s, t1.Token, f.orgA); got.Status != scimtoken.StatusPrevious {
			t.Errorf("t1 status %s, want previous", got.Status)
		}
		if got := mustAuth(t, s, t2.Token, f.orgA); got.Status != scimtoken.StatusCurrent {
			t.Errorf("t2 status %s, want current", got.Status)
		}

		// Rotate again: t1 is N-2 and refused, though never revoked by hand.
		t3, err := s.Rotate(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
		if len(t3.Revoked) != 1 || t3.Revoked[0] != t1.Metadata.ID {
			t.Fatalf("second rotation revoked %v, want [%s]", t3.Revoked, t1.Metadata.ID)
		}
		refused(t, s, t1.Token, "N-2")
		mustAuth(t, s, t2.Token, f.orgA)
		mustAuth(t, s, t3.Token, f.orgA)

		// Revoke N: N-1 works again as the current token (rollback).
		if err := s.Revoke(ctx, f.ownerA, f.orgA, t3.Metadata.ID); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		refused(t, s, t3.Token, "revoked N")
		if got := mustAuth(t, s, t2.Token, f.orgA); got.Status != scimtoken.StatusCurrent {
			t.Errorf("after rollback t2 status %s, want current", got.Status)
		}
		// Revoking again is a no-op.
		if err := s.Revoke(ctx, f.ownerA, f.orgA, t3.Metadata.ID); err != nil {
			t.Fatalf("second Revoke: %v", err)
		}

		// Rotating after the rollback keeps t2 as N-1.
		t4, err := s.Rotate(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatalf("Rotate after rollback: %v", err)
		}
		if t4.Metadata.Generation != 4 || len(t4.Revoked) != 0 {
			t.Fatalf("rotation after rollback: generation %d revoked %v", t4.Metadata.Generation, t4.Revoked)
		}
		mustAuth(t, s, t2.Token, f.orgA)
		mustAuth(t, s, t4.Token, f.orgA)

		list, err := s.List(ctx, f.ownerA, f.orgA)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		want := []scimtoken.Status{scimtoken.StatusCurrent, scimtoken.StatusRevoked, scimtoken.StatusPrevious, scimtoken.StatusRevoked}
		if len(list) != len(want) {
			t.Fatalf("List returned %d tokens, want %d", len(list), len(want))
		}
		for i, tok := range list {
			if tok.Status != want[i] {
				t.Errorf("List[%d] (generation %d) status %s, want %s", i, tok.Generation, tok.Status, want[i])
			}
		}

		if n := len(f.events(t, "scim_token.issued")); n != 1 {
			t.Errorf("issued events: %d, want 1", n)
		}
		if n := len(f.events(t, "scim_token.rotated")); n != 3 {
			t.Errorf("rotated events: %d, want 3", n)
		}
		if n := len(f.events(t, "scim_token.revoked")); n != 1 {
			t.Errorf("revoked events: %d, want 1", n)
		}
		failures := f.events(t, "scim_token.authentication_failed")
		if len(failures) != 2 {
			t.Errorf("authentication failure events: %d, want 2", len(failures))
		}
		for _, e := range failures {
			if e.Outcome != "failure" || e.Context.TenantID == nil || *e.Context.TenantID != f.orgA {
				t.Errorf("failure event: %+v", e)
			}
		}
		assertNoSecrets(t, f, []string{t1.Token, t2.Token, t3.Token, t4.Token})
	})
}

// assertNoSecrets checks that no audit event carries a token or a hash.
func assertNoSecrets(t *testing.T, f *fixture, tokens []string) {
	t.Helper()
	all, err := f.auditEvents.GetBySequence(context.Background(), 1, 1000)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := f.client.ScimToken.Query().All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range all {
		dump := strings.Join([]string{e.Resource.Identifier, fmtAny(e.Details)}, " ")
		for _, tok := range tokens {
			if strings.Contains(dump, tok) {
				t.Fatalf("audit event %s carries a token", e.EventType)
			}
		}
		for _, r := range rows {
			if strings.Contains(dump, r.TokenHash) {
				t.Fatalf("audit event %s carries a token hash", e.EventType)
			}
		}
	}
}

func fmtAny(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		b.WriteString("=")
		switch x := v.(type) {
		case string:
			b.WriteString(x)
		case []string:
			b.WriteString(strings.Join(x, ","))
		}
		b.WriteString(" ")
	}
	return b.String()
}

func TestStoredTokenIsHashed(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	issued, err := s.Issue(context.Background(), f.ownerA, f.orgA, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	row, err := f.client.ScimToken.Get(context.Background(), issued.Metadata.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(row.TokenHash, issued.Token) || strings.Contains(row.TokenHash, issued.Token[len(scimtoken.Prefix):]) {
		t.Fatal("token stored in plaintext")
	}
	if len(row.TokenHash) != 64 {
		t.Fatalf("hash length %d, want 64 hex characters", len(row.TokenHash))
	}
}

func TestCrossTenantTokensStayInTheirTenant(t *testing.T) {
	forEachBackend(t, func(t *testing.T, client *ent.Client) {
		f := newFixture(t, client)
		s := f.service()
		ctx := context.Background()
		a, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.Issue(ctx, f.ownerB, f.orgB, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		mustAuth(t, s, a.Token, f.orgA)
		mustAuth(t, s, b.Token, f.orgB)

		// Rotating B twice does not affect A.
		for range 2 {
			if _, err := s.Rotate(ctx, f.ownerB, f.orgB, scimtoken.IssueOptions{}); err != nil {
				t.Fatal(err)
			}
		}
		mustAuth(t, s, a.Token, f.orgA)

		// Tenant A's owner cannot manage B's tokens.
		if err := s.Revoke(ctx, f.ownerA, f.orgB, b.Metadata.ID); !errors.Is(err, scimtoken.ErrForbidden) {
			t.Fatalf("Revoke in another tenant: %v, want ErrForbidden", err)
		}
		// A token ID of B named under A is not found.
		if err := s.Revoke(ctx, f.ownerA, f.orgA, b.Metadata.ID); !errors.Is(err, scimtoken.ErrNotFound) {
			t.Fatalf("Revoke B's token under A: %v, want ErrNotFound", err)
		}
		if _, err := s.List(ctx, f.ownerA, f.orgB); !errors.Is(err, scimtoken.ErrForbidden) {
			t.Fatalf("List another tenant: %v, want ErrForbidden", err)
		}
	})
}

func TestExpiredAndRevokedTokensAreRefused(t *testing.T) {
	forEachBackend(t, func(t *testing.T, client *ent.Client) {
		f := newFixture(t, client)
		s := f.service()
		ctx := context.Background()
		issued, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{ExpiresIn: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		mustAuth(t, s, issued.Token, f.orgA)
		f.advance(time.Hour)
		refused(t, s, issued.Token, "expired")

		// An expired token does not block issuing a new one.
		fresh, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatalf("Issue after expiry: %v", err)
		}
		if err := s.Revoke(ctx, f.adminA, f.orgA, fresh.Metadata.ID); err != nil {
			t.Fatal(err)
		}
		refused(t, s, fresh.Token, "revoked")

		// Malformed and unknown tokens.
		refused(t, s, "", "empty")
		refused(t, s, fresh.Token[:len(fresh.Token)-1], "truncated")
		tampered := []byte(fresh.Token)
		tampered[len(scimtoken.Prefix)] ^= 1
		refused(t, s, string(tampered), "tampered checksum")
		unknown, err := scimtoken.New(f.client).Issue(ctx, uuid.Nil, f.orgA, scimtoken.IssueOptions{})
		if !errors.Is(err, scimtoken.ErrForbidden) || unknown != nil {
			t.Fatalf("Issue without an authorizer: %v", err)
		}
	})
}

func TestSupersededTokenIsRefused(t *testing.T) {
	// A third unrevoked token can only exist if a row is written outside
	// the service; Authenticate still accepts only the two newest.
	forEachBackend(t, func(t *testing.T, client *ent.Client) {
		f := newFixture(t, client)
		s := f.service()
		ctx := context.Background()
		t1, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t2, err := s.Rotate(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t3, err := s.Rotate(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		// Undo the rotation's revocation of t1.
		if _, err := f.client.ScimToken.UpdateOneID(t1.Metadata.ID).ClearRevokedAt().Save(ctx); err != nil {
			t.Fatal(err)
		}
		refused(t, s, t1.Token, "superseded N-2")
		mustAuth(t, s, t2.Token, f.orgA)
		mustAuth(t, s, t3.Token, f.orgA)
		list, err := s.List(ctx, f.ownerA, f.orgA)
		if err != nil {
			t.Fatal(err)
		}
		if list[2].Status != scimtoken.StatusSuperseded {
			t.Errorf("List status of t1: %s, want superseded", list[2].Status)
		}
	})
}

func TestConcurrentRotationsLeaveAtMostTwoValid(t *testing.T) {
	forEachBackend(t, func(t *testing.T, client *ent.Client) {
		f := newFixture(t, client)
		s := f.service()
		ctx := context.Background()
		first, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		const n = 8
		var (
			wg     sync.WaitGroup
			mu     sync.Mutex
			tokens = []string{first.Token}
			ok     int
		)
		for range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				issued, err := s.Rotate(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					if !errors.Is(err, scimtoken.ErrConflict) {
						t.Errorf("Rotate: %v", err)
					}
					return
				}
				ok++
				tokens = append(tokens, issued.Token)
			}()
		}
		wg.Wait()
		if ok == 0 {
			t.Fatal("no rotation succeeded")
		}
		valid := 0
		for _, tok := range tokens {
			if _, err := s.Authenticate(ctx, tok); err == nil {
				valid++
			} else if !errors.Is(err, scimtoken.ErrInvalidToken) {
				t.Fatalf("Authenticate: %v", err)
			}
		}
		if valid != scimtoken.MaxValid {
			t.Fatalf("%d tokens authenticate after %d rotations, want %d", valid, ok, scimtoken.MaxValid)
		}
		unrevoked, err := f.client.ScimToken.Query().Where().All(ctx)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, r := range unrevoked {
			if r.RevokedAt == nil {
				count++
			}
		}
		if count > scimtoken.MaxValid {
			t.Fatalf("%d unrevoked tokens, want at most %d", count, scimtoken.MaxValid)
		}
	})
}

func TestManagementAuthorization(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	ctx := context.Background()
	if _, err := s.Issue(ctx, f.memberA, f.orgA, scimtoken.IssueOptions{}); !errors.Is(err, scimtoken.ErrForbidden) {
		t.Fatalf("member Issue: %v, want ErrForbidden", err)
	}
	if _, err := s.Issue(ctx, uuid.Nil, f.orgA, scimtoken.IssueOptions{}); !errors.Is(err, scimtoken.ErrForbidden) {
		t.Fatalf("anonymous Issue: %v, want ErrForbidden", err)
	}
	if _, err := s.Issue(ctx, f.platform, f.orgA, scimtoken.IssueOptions{}); err != nil {
		t.Fatalf("platform admin Issue: %v", err)
	}
	if _, err := s.Rotate(ctx, f.adminA, f.orgA, scimtoken.IssueOptions{}); err != nil {
		t.Fatalf("admin Rotate: %v", err)
	}
	if _, err := s.List(ctx, f.memberA, f.orgA); !errors.Is(err, scimtoken.ErrForbidden) {
		t.Fatalf("member List: %v, want ErrForbidden", err)
	}
	if _, err := s.Issue(ctx, f.platform, uuid.New(), scimtoken.IssueOptions{}); !errors.Is(err, scimtoken.ErrOrganizationNotFound) {
		t.Fatalf("Issue for a missing organization: %v, want ErrOrganizationNotFound", err)
	}
}

func TestDeletedOrganizationTokensAreRefused(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service()
	ctx := context.Background()
	issued, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Organization.UpdateOneID(f.orgA).SetActive(false).Save(ctx); err != nil {
		t.Fatal(err)
	}
	refused(t, s, issued.Token, "deleted organization")
}

func TestLastUsedIsThrottled(t *testing.T) {
	f := newFixture(t, openSQLite(t))
	s := f.service(scimtoken.WithLastUsedInterval(time.Minute))
	ctx := context.Background()
	issued, err := s.Issue(ctx, f.ownerA, f.orgA, scimtoken.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	lastUsed := func() time.Time {
		t.Helper()
		row, err := f.client.ScimToken.Get(ctx, issued.Metadata.ID)
		if err != nil {
			t.Fatal(err)
		}
		if row.LastUsedAt == nil {
			return time.Time{}
		}
		return row.LastUsedAt.UTC()
	}
	start := f.now()
	mustAuth(t, s, issued.Token, f.orgA)
	if got := lastUsed(); !got.Equal(start) {
		t.Fatalf("last used %v, want %v", got, start)
	}
	f.advance(30 * time.Second)
	mustAuth(t, s, issued.Token, f.orgA)
	if got := lastUsed(); !got.Equal(start) {
		t.Fatalf("last used rewritten within the interval: %v", got)
	}
	f.advance(31 * time.Second)
	mustAuth(t, s, issued.Token, f.orgA)
	if got := lastUsed(); !got.Equal(f.now()) {
		t.Fatalf("last used %v, want %v", got, f.now())
	}
}
