package mode_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/mode"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/internal/pgtest"
)

// recVocabulary is an application with an organization facet holding its
// roles and a resource type accepting collaborators.
type recVocabulary struct{}

func (recVocabulary) App() string { return "recdemo" }
func (recVocabulary) Roles() authz.RolePermissions {
	return authz.RolePermissions{"admin": {"doc.manage"}, "editor": {"doc.edit"}}
}
func (recVocabulary) Hierarchy() authz.RoleHierarchy {
	return authz.RoleHierarchy{"editor": 10, "admin": 20}
}
func (recVocabulary) Scopes() []string { return nil }
func (recVocabulary) SpiceDBSchema() string {
	return `definition recdemo_org {
    relation org: organization
    relation admin: principal
    relation editor: principal

    permission edit = editor + admin + org->manage
}
` + authz.ResourceRoleFragment("recdemo_doc")
}

func recRegistry(t *testing.T) *authz.VocabularyRegistry {
	t.Helper()
	r := authz.NewVocabularyRegistry()
	if err := r.Register(recVocabulary{}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return r
}

// fakeGraph is an in-memory Graph. Its hooks let a test act between the
// reconciler's steps.
type fakeGraph struct {
	mu   sync.Mutex
	rels map[spicedb.Relationship]struct{}

	afterRead    func(resourceType string)
	beforeDelete func(rels []*spicedb.Relationship)
	failWrites   error
}

func newFakeGraph() *fakeGraph { return &fakeGraph{rels: map[spicedb.Relationship]struct{}{}} }

func (g *fakeGraph) ReadRelationships(_ context.Context, f *spicedb.RelationshipFilter, pageSize int, fn func(*spicedb.Relationship) error) error {
	g.mu.Lock()
	var out []spicedb.Relationship
	for r := range g.rels {
		if r.ResourceType == f.ResourceType && (f.ResourceID == "" || r.ResourceID == f.ResourceID) &&
			(f.Relation == "" || r.Relation == f.Relation) && (f.SubjectType == "" || r.SubjectType == f.SubjectType) &&
			(f.SubjectID == "" || r.SubjectID == f.SubjectID) {
			out = append(out, r)
		}
	}
	g.mu.Unlock()
	if pageSize <= 0 {
		return errors.New("fake: page size not set")
	}
	for i := range out {
		if err := fn(&out[i]); err != nil {
			return err
		}
	}
	if g.afterRead != nil {
		g.afterRead(f.ResourceType)
	}
	return nil
}

func (g *fakeGraph) WriteRelationships(_ context.Context, rels []*spicedb.Relationship) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failWrites != nil {
		return g.failWrites
	}
	for _, r := range rels {
		g.rels[*r] = struct{}{}
	}
	return nil
}

func (g *fakeGraph) DeleteRelationshipsExact(_ context.Context, rels []*spicedb.Relationship) error {
	if g.beforeDelete != nil {
		g.beforeDelete(rels)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range rels {
		delete(g.rels, *r)
	}
	return nil
}

func (g *fakeGraph) add(rels ...spicedb.Relationship) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, r := range rels {
		g.rels[r] = struct{}{}
	}
}

func (g *fakeGraph) has(r spicedb.Relationship) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, ok := g.rels[r]
	return ok
}

func (g *fakeGraph) all() []spicedb.Relationship {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []spicedb.Relationship
	for r := range g.rels {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b spicedb.Relationship) int {
		return cmp.Compare(fmt.Sprint(a), fmt.Sprint(b))
	})
	return out
}

func pr(resourceType, resourceID, relation string, subject uuid.UUID) spicedb.Relationship {
	return spicedb.Relationship{ResourceType: resourceType, ResourceID: resourceID, Relation: relation, SubjectType: spicedb.TypePrincipal, SubjectID: subject.String()}
}

// world is a populated identity database and the relationships it calls
// for.
type world struct {
	db      *ent.Client
	org     uuid.UUID // active organization
	gone    uuid.UUID // deleted organization
	owner   uuid.UUID
	member  uuid.UUID
	paused  uuid.UUID // deactivated member
	collab  uuid.UUID
	admin   uuid.UUID // platform administrator
	managed uuid.UUID
	off     uuid.UUID // deactivated principal holding every kind of access
	desired []spicedb.Relationship
}

func newWorld(t *testing.T, db *ent.Client) *world {
	t.Helper()
	ctx := context.Background()
	person := func(admin bool) uuid.UUID {
		t.Helper()
		p, err := db.Principal.Create().SetType(principal.TypeHuman).SetIdentifier(uuid.NewString() + "@example.com").SetDisplayName("P").Save(ctx)
		if err != nil {
			t.Fatalf("principal: %v", err)
		}
		if _, err := db.Human.Create().SetPrincipalID(p.ID).SetEmail(p.Identifier).SetIsPlatformAdmin(admin).Save(ctx); err != nil {
			t.Fatalf("human: %v", err)
		}
		return p.ID
	}
	org := func(active bool) uuid.UUID {
		t.Helper()
		o, err := db.Organization.Create().SetName("Org").SetSlug("org-" + uuid.NewString()[:8]).SetActive(active).Save(ctx)
		if err != nil {
			t.Fatalf("organization: %v", err)
		}
		return o.ID
	}
	member := func(o, p uuid.UUID, role string, active bool) {
		t.Helper()
		if _, err := db.PrincipalMembership.Create().SetOrganizationID(o).SetPrincipalID(p).SetRole(role).SetActive(active).Save(ctx); err != nil {
			t.Fatalf("membership: %v", err)
		}
	}
	w := &world{db: db, org: org(true), gone: org(false)}
	w.owner, w.member, w.paused, w.collab, w.admin, w.managed = person(false), person(false), person(false), person(false), person(true), person(false)
	w.off = person(true)
	if _, err := db.Principal.UpdateOneID(w.off).SetActive(false).Save(ctx); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	member(w.org, w.off, "member", true)
	member(w.org, w.owner, "owner", true)
	member(w.org, w.member, "member", true)
	member(w.org, w.paused, "admin", false)
	member(w.org, w.collab, "collaborator", true)
	member(w.gone, w.owner, "owner", true)
	member(w.gone, w.member, "member", true)
	for _, ar := range []struct {
		o, p uuid.UUID
		role string
	}{{w.org, w.member, "editor"}, {w.org, w.paused, "admin"}, {w.gone, w.member, "admin"}, {w.org, w.collab, "editor"}, {w.org, w.off, "editor"}} {
		if _, err := db.AppRole.Create().SetOrganizationID(ar.o).SetPrincipalID(ar.p).SetApplication("recdemo").SetRole(ar.role).Save(ctx); err != nil {
			t.Fatalf("app role: %v", err)
		}
	}
	for _, g := range []struct {
		o, p     uuid.UUID
		id, role string
	}{{w.org, w.collab, "d1", "viewer"}, {w.org, w.paused, "d2", "maintainer"}, {w.gone, w.member, "d3", "contributor"}, {w.org, w.off, "d4", "viewer"}} {
		if _, err := db.ResourceGrant.Create().SetOrganizationID(g.o).SetPrincipalID(g.p).SetResourceType("recdemo_doc").SetResourceID(g.id).SetRole(g.role).Save(ctx); err != nil {
			t.Fatalf("grant: %v", err)
		}
	}
	if _, err := db.ManagerRelationship.Create().SetManagedPrincipalID(w.managed).SetManagerPrincipalID(w.owner).SetRole("guardian").Save(ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := db.ManagerRelationship.Create().SetManagedPrincipalID(w.managed).SetManagerPrincipalID(w.member).SetRole("educator").SetActive(false).Save(ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}
	if _, err := db.ManagerRelationship.Create().SetManagedPrincipalID(w.managed).SetManagerPrincipalID(w.off).SetRole("educator").Save(ctx); err != nil {
		t.Fatalf("manager: %v", err)
	}
	o := w.org.String()
	w.desired = []spicedb.Relationship{
		pr("organization", o, "owner", w.owner),
		pr("organization", o, "member", w.member),
		pr("organization", o, "collaborator", w.collab),
		pr("recdemo_org", o, "editor", w.member),
		pr("recdemo_doc", "d1", "viewer", w.collab),
		pr("platform", "global", "admin", w.admin),
		pr("principal", w.managed.String(), "guardian", w.owner),
	}
	return w
}

// stale returns relationships the tables do not call for: the deactivated
// member's, the deleted organization's, an ended manager relation, a
// removed platform administrator, a higher role than the one held, a
// collaborator's application role, and every relationship of a
// deactivated principal.
func (w *world) stale() []spicedb.Relationship {
	o, gone := w.org.String(), w.gone.String()
	return []spicedb.Relationship{
		pr("organization", o, "admin", w.paused),
		pr("organization", o, "admin", w.member),
		pr("organization", gone, "owner", w.owner),
		pr("recdemo_org", o, "admin", w.paused),
		pr("recdemo_org", gone, "admin", w.member),
		pr("recdemo_doc", "d2", "maintainer", w.paused),
		pr("recdemo_doc", "d3", "contributor", w.member),
		pr("recdemo_doc", "d1", "maintainer", w.collab),
		pr("platform", "global", "admin", w.owner),
		pr("principal", w.managed.String(), "educator", w.member),
		pr("recdemo_org", o, "editor", w.collab),
		pr("organization", o, "member", w.off),
		pr("recdemo_org", o, "editor", w.off),
		pr("recdemo_doc", "d4", "viewer", w.off),
		pr("platform", "global", "admin", w.off),
		pr("principal", w.managed.String(), "educator", w.off),
	}
}

// foreign returns relationships the reconciler does not manage, which it
// must leave alone.
func (w *world) foreign() []spicedb.Relationship {
	return []spicedb.Relationship{
		{ResourceType: "recdemo_doc", ResourceID: "d1", Relation: "org", SubjectType: "organization", SubjectID: w.org.String()},
		{ResourceType: "recdemo_org", ResourceID: w.org.String(), Relation: "org", SubjectType: "organization", SubjectID: w.org.String()},
	}
}

func newReconciler(db *ent.Client, g mode.Graph, t *testing.T) *mode.Reconciler {
	return mode.NewReconciler(db, g, mode.WithReconcileRegistry(recRegistry(t)), mode.WithReconcilePageSize(2))
}

func TestReconcileRepairsDriftBothWays(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, newDB(t))
	g := newFakeGraph()
	// Half of the desired relationships are present, the rest missing.
	for i, r := range w.desired {
		if i%2 == 0 {
			g.add(r)
		}
	}
	g.add(w.stale()...)
	g.add(w.foreign()...)

	rc := newReconciler(w.db, g, t)
	res, err := rc.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	want := append(slices.Clone(w.desired), w.foreign()...)
	slices.SortFunc(want, func(a, b spicedb.Relationship) int { return cmp.Compare(fmt.Sprint(a), fmt.Sprint(b)) })
	if got := g.all(); !slices.Equal(got, want) {
		t.Errorf("graph after reconcile:\n got %v\nwant %v", got, want)
	}
	if res.Added != len(w.desired)/2 || res.Removed != len(w.stale()) || res.Desired != len(w.desired) || res.Restored != 0 || res.Skipped != 0 {
		t.Errorf("result = %+v", res)
	}

	// A second run finds nothing to do.
	res, err = rc.Reconcile(ctx)
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if res.Added != 0 || res.Removed != 0 || res.Checked != len(w.desired) {
		t.Errorf("second result = %+v, want no changes", res)
	}
	if s := rc.Stats(); s.Runs != 2 || s.Failures != 0 || s.Added != int64(len(w.desired)/2) || s.Last.Checked != len(w.desired) {
		t.Errorf("stats = %+v", s)
	}
}

// A grant committed while the reconciler runs is not removed: one
// committed after the graph was read is in the tables, and one committed
// after the tables were read, whose relationship the reconciler then
// deletes as stale, is written back.
func TestReconcileKeepsGrantsCommittedDuringTheRun(t *testing.T) {
	ctx := context.Background()
	w := newWorld(t, newDB(t))
	g := newFakeGraph()
	g.add(w.desired...)

	// A new member granted right after the organization relationships
	// were read: the grant path commits the row, then writes the graph.
	late := uuid.New()
	if _, err := w.db.Principal.Create().SetID(late).SetType(principal.TypeHuman).SetIdentifier("late@example.com").SetDisplayName("L").Save(ctx); err != nil {
		t.Fatal(err)
	}
	lateRel := pr("organization", w.org.String(), "member", late)
	g.afterRead = func(resourceType string) {
		if resourceType != "organization" {
			return
		}
		g.afterRead = nil
		if _, err := w.db.PrincipalMembership.Create().SetOrganizationID(w.org).SetPrincipalID(late).SetRole("member").Save(ctx); err != nil {
			t.Error(err)
		}
		g.add(lateRel)
	}

	// A relationship left in the graph by an earlier membership is stale,
	// and is granted again between the reconciler's read of the tables and
	// its delete.
	regranted := pr("organization", w.org.String(), "admin", w.paused)
	g.add(regranted)
	g.beforeDelete = func(rels []*spicedb.Relationship) {
		if !slices.ContainsFunc(rels, func(r *spicedb.Relationship) bool { return *r == regranted }) {
			return
		}
		if _, err := w.db.PrincipalMembership.Update().
			Where(principalmembership.OrganizationID(w.org), principalmembership.PrincipalID(w.paused)).
			SetActive(true).Save(ctx); err != nil {
			t.Error(err)
		}
		g.add(regranted)
	}

	res, err := newReconciler(w.db, g, t).Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !g.has(lateRel) {
		t.Error("the grant committed after the graph was read was removed")
	}
	if !g.has(regranted) {
		t.Error("the grant committed after the tables were read was removed")
	}
	if res.Restored != 1 {
		t.Errorf("restored = %d, want 1 (%+v)", res.Restored, res)
	}
}

func TestReconcileReportsGraphFailures(t *testing.T) {
	w := newWorld(t, newDB(t))
	g := newFakeGraph()
	boom := errors.New("graph down")
	g.failWrites = boom
	rc := newReconciler(w.db, g, t)
	if _, err := rc.Reconcile(context.Background()); !errors.Is(err, boom) {
		t.Errorf("Reconcile = %v, want the graph error", err)
	}
	if s := rc.Stats(); s.Failures != 1 || !errors.Is(s.LastError, boom) {
		t.Errorf("stats = %+v", s)
	}
}

func TestReconcilerRunsOnSchedule(t *testing.T) {
	w := newWorld(t, newDB(t))
	rc := newReconciler(w.db, newFakeGraph(), t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- rc.Run(ctx, mode.ReconcileSchedule{OnStartup: true, Interval: 10 * time.Millisecond, Jitter: 5 * time.Millisecond})
	}()
	deadline := time.Now().Add(10 * time.Second)
	for rc.Stats().Runs < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("runs = %d after 10s", rc.Stats().Runs)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run = %v", err)
	}

	// Without an interval Run returns after the startup run.
	rc = newReconciler(w.db, newFakeGraph(), t)
	if err := rc.Run(context.Background(), mode.ReconcileSchedule{OnStartup: true}); err != nil || rc.Stats().Runs != 1 {
		t.Errorf("startup-only Run = %v, runs %d", err, rc.Stats().Runs)
	}
}

// On PostgreSQL the reconciler does not restore a relationship a
// revocation in progress has removed: its repair waits for the
// revocation's graph lock and then finds the rows gone.
func TestReconcileWaitsForRevocationsPostgres(t *testing.T) {
	ctx := context.Background()
	sqlDB := pgtest.Open(t)
	db := ent.NewClient(ent.Driver(entsql.OpenDB(dialect.Postgres, sqlDB)))
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := db.Schema.Create(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	w := newWorld(t, db)
	g := newFakeGraph()
	g.add(w.desired...)
	revoked := pr("organization", w.org.String(), "member", w.member)

	// A revocation of the member: it deletes the row, takes the lock and
	// removes the relationship, and has not committed yet.
	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.PrincipalMembership.Delete().
		Where(principalmembership.OrganizationID(w.org), principalmembership.PrincipalID(w.member)).
		Exec(ctx); err != nil {
		t.Fatal(err)
	}
	if err := graphlock.Lock(ctx, tx, graphlock.Principal(w.member)); err != nil {
		t.Fatal(err)
	}
	if err := g.DeleteRelationshipsExact(ctx, []*spicedb.Relationship{&revoked}); err != nil {
		t.Fatal(err)
	}

	type outcome struct {
		res mode.ReconcileResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := newReconciler(db, g, t).Reconcile(ctx)
		done <- outcome{res, err}
	}()
	select {
	case o := <-done:
		t.Fatalf("Reconcile finished while the revocation held the lock: %+v, %v", o.res, o.err)
	case <-time.After(300 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	o := <-done
	if o.err != nil {
		t.Fatalf("Reconcile: %v", o.err)
	}
	if g.has(revoked) {
		t.Error("the reconciler restored a relationship a revocation removed")
	}
	if o.res.Skipped == 0 {
		t.Errorf("result = %+v, want the revoked relationship skipped", o.res)
	}
}
