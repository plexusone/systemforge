package mode

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/approle"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/resourcegrant"
	"github.com/plexusone/systemforge/identity/graphlock"
	"github.com/plexusone/systemforge/identity/graphstate"
)

// Graph is the relationship store a Reconciler repairs. *spicedb.Client
// implements it.
type Graph interface {
	// ReadRelationships calls fn for every relationship matching filter,
	// as one consistent snapshot read pageSize at a time.
	ReadRelationships(ctx context.Context, filter *spicedb.RelationshipFilter, pageSize int, fn func(*spicedb.Relationship) error) error
	// WriteRelationships writes relationships; writing one that exists
	// succeeds.
	WriteRelationships(ctx context.Context, rels []*spicedb.Relationship) error
	// DeleteRelationshipsExact deletes relationships; deleting one that
	// is absent succeeds.
	DeleteRelationshipsExact(ctx context.Context, rels []*spicedb.Relationship) error
}

var _ Graph = (*spicedb.Client)(nil)

// DefaultReconcilePageSize is how many rows or relationships the
// reconciler reads per request when the configuration does not say.
const DefaultReconcilePageSize = 500

// ReconcileResult reports one reconciliation.
type ReconcileResult struct {
	Started  time.Time
	Duration time.Duration

	// Checked is the number of relationships read from the graph that the
	// reconciler manages, and Desired the number the identity tables call
	// for.
	Checked int
	Desired int

	// Added is the number of missing relationships written, and Removed
	// the number of stale relationships deleted. Restored counts deleted
	// relationships written back because a grant committed while the
	// reconciliation ran; Skipped counts missing relationships not
	// written because a revocation removed their rows meanwhile.
	Added    int
	Removed  int
	Restored int
	Skipped  int

	// Namespaces breaks the counts down by the graph definition
	// reconciled ("organization", "platform", "principal", an
	// application's "{app}_org", or a resource type).
	Namespaces []NamespaceResult
}

// NamespaceResult is the part of a ReconcileResult for one definition.
type NamespaceResult struct {
	Namespace string
	Checked   int
	Desired   int
	Added     int
	Removed   int
	Restored  int
	Skipped   int
}

// ReconcileStats are a Reconciler's totals since it was created, for
// metrics.
type ReconcileStats struct {
	Runs     int64
	Failures int64
	Added    int64
	Removed  int64
	Restored int64
	Skipped  int64
	// Last is the result of the last successful run, zero before one.
	Last ReconcileResult
	// LastError is the error of the last run, nil when it succeeded.
	LastError error
}

// Reconciler repairs the authorization graph from the identity tables,
// which are the record: it writes the relationships the tables call for
// that the graph lacks, and deletes those it holds that the tables no
// longer call for. It manages the relationships the identity services
// write — organization memberships, platform administration, manager
// relations, application roles on "{app}_org" facets and resource grants
// on collaborator resource types — and never touches others, such as the
// "org" relation an application writes on its own resources.
//
// The identity services remove a relationship before the change that
// revokes it commits, so the graph never holds more than the tables
// record for long; the reconciler repairs what is left behind when a
// commit fails after the removal, when a grant could not be written, or
// when a grant and a revocation of the same access race.
//
// A reconciliation is safe while the services run. For each definition it
// reads the graph first and the tables second, so a grant committed after
// the graph was read is in the tables and is not deleted. It writes a
// missing relationship only in a transaction holding the graph locks of
// its principal and organization (package identity/graphlock), after
// reading its rows again, so a revocation in progress is never undone. It
// reads the rows of every relationship it deleted again afterwards and
// restores one a grant committed in the meantime. The locks need
// PostgreSQL; on SQLite the reconciler does not serialize with
// revocations.
//
// What the tables call for follows package identity/graphstate, which the
// services also consult before writing a grant: in particular, a
// deactivated principal and a collaborator's application roles call for
// nothing.
//
// It holds one definition's relationships in memory at a time.
type Reconciler struct {
	db       *ent.Client
	graph    Graph
	registry *authz.VocabularyRegistry
	pageSize int
	logger   *slog.Logger

	run   sync.Mutex // one reconciliation at a time
	mu    sync.Mutex // guards stats
	stats ReconcileStats
}

// ReconcilerOption configures a Reconciler.
type ReconcilerOption func(*Reconciler)

// WithReconcileRegistry names the application vocabularies whose
// application roles and resource grants the reconciler manages. Without
// it, it manages the resource types found in the grants table and no
// application roles.
func WithReconcileRegistry(r *authz.VocabularyRegistry) ReconcilerOption {
	return func(rc *Reconciler) { rc.registry = r }
}

// WithReconcilePageSize sets how many rows or relationships are read per
// request. Default DefaultReconcilePageSize.
func WithReconcilePageSize(n int) ReconcilerOption {
	return func(rc *Reconciler) {
		if n > 0 {
			rc.pageSize = n
		}
	}
}

// WithReconcileLogger sets the logger for summaries and failures. The
// summary is logged at info level and carries counts only; the
// relationships changed, with their identifiers, are logged at debug.
func WithReconcileLogger(l *slog.Logger) ReconcilerOption {
	return func(rc *Reconciler) {
		if l != nil {
			rc.logger = l
		}
	}
}

// NewReconciler returns a Reconciler of graph from db.
func NewReconciler(db *ent.Client, graph Graph, opts ...ReconcilerOption) *Reconciler {
	r := &Reconciler{db: db, graph: graph, pageSize: DefaultReconcilePageSize, logger: slog.Default()}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Stats returns the reconciler's totals.
func (r *Reconciler) Stats() ReconcileStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.stats
	s.Last.Namespaces = slices.Clone(s.Last.Namespaces)
	return s
}

// ReconcileSchedule says when Run reconciles.
type ReconcileSchedule struct {
	// OnStartup reconciles as soon as Run starts.
	OnStartup bool
	// Interval is the time between periodic reconciliations; zero or
	// less disables them.
	Interval time.Duration
	// Jitter adds a random delay of up to Jitter to every interval, so
	// several instances do not reconcile in step.
	Jitter time.Duration
}

// Run reconciles on schedule until ctx is cancelled, then returns nil. A
// failed reconciliation is logged and counted in Stats, and the schedule
// goes on. With no interval it returns after the startup run.
func (r *Reconciler) Run(ctx context.Context, s ReconcileSchedule) error {
	if s.OnStartup {
		r.reconcileLogged(ctx)
	}
	if s.Interval <= 0 {
		return nil
	}
	for {
		wait := s.Interval
		if s.Jitter > 0 {
			wait += rand.N(s.Jitter) //nolint:gosec // G404: scheduling jitter, not a secret
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		r.reconcileLogged(ctx)
	}
}

func (r *Reconciler) reconcileLogged(ctx context.Context) {
	if _, err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
		r.logger.ErrorContext(ctx, "authorization graph reconciliation failed", "error", err)
	}
}

// Reconcile repairs the graph once and reports what it changed. Calls are
// serialized. On an error the repairs made before it stand and are
// counted in the result.
func (r *Reconciler) Reconcile(ctx context.Context) (ReconcileResult, error) {
	r.run.Lock()
	defer r.run.Unlock()
	res := ReconcileResult{Started: time.Now()}
	namespaces, err := r.namespaces(ctx)
	if err == nil {
		for _, ns := range namespaces {
			nr, nerr := r.reconcileNamespace(ctx, ns)
			res.add(nr)
			if nerr != nil {
				err = fmt.Errorf("authz/mode: reconciling %s: %w", ns.name, nerr)
				break
			}
		}
	}
	res.Duration = time.Since(res.Started)
	r.record(res, err)
	attrs := []any{
		"checked", res.Checked, "desired", res.Desired, "added", res.Added, "removed", res.Removed,
		"restored", res.Restored, "skipped", res.Skipped, "duration", res.Duration,
	}
	switch {
	case err != nil:
	case res.Added+res.Removed+res.Restored > 0:
		r.logger.InfoContext(ctx, "authorization graph reconciled; repaired drift", attrs...)
	default:
		r.logger.InfoContext(ctx, "authorization graph reconciled; no drift", attrs...)
	}
	return res, err
}

func (res *ReconcileResult) add(n NamespaceResult) {
	res.Checked += n.Checked
	res.Desired += n.Desired
	res.Added += n.Added
	res.Removed += n.Removed
	res.Restored += n.Restored
	res.Skipped += n.Skipped
	res.Namespaces = append(res.Namespaces, n)
}

func (r *Reconciler) record(res ReconcileResult, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stats.Runs++
	r.stats.Added += int64(res.Added)
	r.stats.Removed += int64(res.Removed)
	r.stats.Restored += int64(res.Restored)
	r.stats.Skipped += int64(res.Skipped)
	r.stats.LastError = err
	if err != nil {
		r.stats.Failures++
		return
	}
	r.stats.Last = res
}

// rel is a relationship as a comparable value.
type rel = spicedb.Relationship

// namespace is one graph definition the reconciler manages.
type namespace struct {
	name string
	// filter selects the definition's relationships in the graph.
	filter spicedb.RelationshipFilter
	// manages reports whether a relationship read is the reconciler's.
	manages func(rel) bool
	// desired calls fn for every relationship the tables call for.
	desired func(ctx context.Context, fn func(rel)) error
	// locks returns the graph locks of a relationship.
	locks func(ctx context.Context, x rel) ([]string, error)
	// confirm reports, inside a transaction holding the locks named by
	// keys, whether the tables still call for the relationship.
	confirm func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error)
}

func (r *Reconciler) reconcileNamespace(ctx context.Context, ns namespace) (NamespaceResult, error) {
	out := NamespaceResult{Namespace: ns.name}

	// The graph first, then the tables: see the Reconciler documentation.
	have := map[rel]struct{}{}
	filter := ns.filter
	if err := r.graph.ReadRelationships(ctx, &filter, r.pageSize, func(x *spicedb.Relationship) error {
		if ns.manages(*x) {
			have[*x] = struct{}{}
		}
		return nil
	}); err != nil {
		return out, err
	}
	want := map[rel]struct{}{}
	if err := ns.desired(ctx, func(x rel) { want[x] = struct{}{} }); err != nil {
		return out, err
	}
	out.Checked, out.Desired = len(have), len(want)

	var stale, missing []rel
	for x := range have {
		if _, ok := want[x]; !ok {
			stale = append(stale, x)
		}
	}
	for x := range want {
		if _, ok := have[x]; !ok {
			missing = append(missing, x)
		}
	}
	sortRels(stale)
	sortRels(missing)
	have, want = nil, nil

	for batch := range slices.Chunk(stale, r.pageSize) {
		ptrs := make([]*spicedb.Relationship, len(batch))
		for i := range batch {
			ptrs[i] = &batch[i]
		}
		if err := r.graph.DeleteRelationshipsExact(ctx, ptrs); err != nil {
			return out, err
		}
		out.Removed += len(batch)
		for _, x := range batch {
			r.logger.DebugContext(ctx, "authorization graph: removed stale relationship", relAttrs(x)...)
		}
	}
	// A grant committed after the tables were read may have written one of
	// the deleted relationships before the delete: write it back if its
	// rows now call for it.
	for _, x := range stale {
		written, err := r.repair(ctx, ns, x)
		if err != nil {
			return out, err
		}
		if written {
			out.Restored++
		}
	}
	for _, x := range missing {
		written, err := r.repair(ctx, ns, x)
		if err != nil {
			return out, err
		}
		if written {
			out.Added++
		} else {
			out.Skipped++
		}
	}
	return out, nil
}

// repair writes a relationship if its rows call for it, in a transaction
// holding its graph locks, and reports whether it wrote it.
func (r *Reconciler) repair(ctx context.Context, ns namespace, x rel) (written bool, err error) {
	keys, err := ns.locks(ctx, x)
	if err != nil {
		return false, err
	}
	tx, err := r.db.Tx(ctx)
	if err != nil {
		return false, fmt.Errorf("starting transaction: %w", err)
	}
	defer func() {
		// The transaction only reads and holds the locks; ending it
		// releases them.
		if rerr := tx.Rollback(); rerr != nil && !errors.Is(rerr, context.Canceled) {
			err = errors.Join(err, fmt.Errorf("ending transaction: %w", rerr))
		}
	}()
	if err = graphlock.Lock(ctx, tx, keys...); err != nil {
		return false, err
	}
	ok, err := ns.confirm(ctx, tx, x, keys)
	if err != nil || !ok {
		return false, err
	}
	if err = r.graph.WriteRelationships(ctx, []*spicedb.Relationship{&x}); err != nil {
		return false, err
	}
	r.logger.DebugContext(ctx, "authorization graph: wrote missing relationship", relAttrs(x)...)
	return true, nil
}

func relAttrs(x rel) []any {
	return []any{
		"resource_type", x.ResourceType, "resource_id", x.ResourceID, "relation", x.Relation,
		"subject_type", x.SubjectType, "subject_id", x.SubjectID,
	}
}

func sortRels(rels []rel) {
	slices.SortFunc(rels, func(a, b rel) int {
		return cmp.Or(
			cmp.Compare(a.ResourceType, b.ResourceType), cmp.Compare(a.ResourceID, b.ResourceID),
			cmp.Compare(a.Relation, b.Relation), cmp.Compare(a.SubjectType, b.SubjectType),
			cmp.Compare(a.SubjectID, b.SubjectID))
	})
}

// namespaces lists the definitions to reconcile.
func (r *Reconciler) namespaces(ctx context.Context) ([]namespace, error) {
	out := []namespace{r.organizations(), r.platform(), r.managers()}
	if r.registry != nil {
		for _, app := range r.registry.Apps() {
			if r.registry.HasOrgFacet(app) {
				out = append(out, r.appRoles(app))
			}
		}
	}
	types, err := r.grantTypes(ctx)
	if err != nil {
		return nil, err
	}
	for _, t := range types {
		out = append(out, r.grants(t))
	}
	return out, nil
}

func (r *Reconciler) grantTypes(ctx context.Context) ([]string, error) {
	if r.registry != nil {
		var types []string
		for _, app := range r.registry.Apps() {
			types = append(types, r.registry.CollaboratorResourceTypes(app)...)
		}
		slices.Sort(types)
		return slices.Compact(types), nil
	}
	types, err := r.db.ResourceGrant.Query().Unique(true).Select(resourcegrant.FieldResourceType).Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("authz/mode: listing resource types: %w", err)
	}
	slices.Sort(types)
	return types, nil
}

// principalRel is a relationship to a principal subject.
func principalRel(resourceType, resourceID, relation string, subject uuid.UUID) rel {
	return rel{ResourceType: resourceType, ResourceID: resourceID, Relation: relation, SubjectType: spicedb.TypePrincipal, SubjectID: subject.String()}
}

// ids parses the resource and subject identifiers of a relationship whose
// resource is a principal or an organization. A relationship whose
// identifiers are not UUIDs is not one the tables can call for.
func ids(x rel) (resource, subject uuid.UUID, ok bool) {
	res, err1 := uuid.Parse(x.ResourceID)
	sub, err2 := uuid.Parse(x.SubjectID)
	return res, sub, err1 == nil && err2 == nil
}

func subjectID(x rel) (uuid.UUID, bool) {
	id, err := uuid.Parse(x.SubjectID)
	return id, err == nil
}

// orgPrincipalLocks locks the organization and principal of a
// relationship on an organization or its facet.
func orgPrincipalLocks(_ context.Context, x rel) ([]string, error) {
	org, p, ok := ids(x)
	if !ok {
		return nil, nil
	}
	return []string{graphlock.Organization(org), graphlock.Principal(p)}, nil
}

// organizations: organization:{org}#{role}@principal:{p} for every active
// membership of an active organization held by an active principal.
func (r *Reconciler) organizations() namespace {
	orgRelations := graphstate.OrgRoles()
	return namespace{
		name:   spicedb.TypeOrganization,
		filter: spicedb.RelationshipFilter{ResourceType: spicedb.TypeOrganization, SubjectType: spicedb.TypePrincipal},
		manages: func(x rel) bool {
			return slices.Contains(orgRelations, x.Relation)
		},
		desired: func(ctx context.Context, fn func(rel)) error {
			last := uuid.Nil
			for {
				rows, err := r.db.PrincipalMembership.Query().
					Where(principalmembership.IDGT(last)).
					Where(graphstate.HoldingMemberships()...).
					Order(ent.Asc(principalmembership.FieldID)).
					Limit(r.pageSize).
					All(ctx)
				if err != nil {
					return fmt.Errorf("reading memberships: %w", err)
				}
				for _, m := range rows {
					fn(principalRel(spicedb.TypeOrganization, m.OrganizationID.String(), m.Role, m.PrincipalID))
				}
				if len(rows) < r.pageSize {
					return nil
				}
				last = rows[len(rows)-1].ID
			}
		},
		locks: orgPrincipalLocks,
		confirm: func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error) {
			org, p, ok := ids(x)
			if !ok || !slices.Contains(orgRelations, x.Relation) {
				return false, nil
			}
			return graphstate.Membership(ctx, tx.Client(), org, p, x.Relation)
		},
	}
}

const (
	platformType = "platform"
	platformID   = "global"
)

// platform: platform:global#admin@principal:{p} for every active platform
// administrator.
func (r *Reconciler) platform() namespace {
	return namespace{
		name:   platformType,
		filter: spicedb.RelationshipFilter{ResourceType: platformType, SubjectType: spicedb.TypePrincipal},
		manages: func(x rel) bool {
			return x.ResourceID == platformID && x.Relation == spicedb.RelAdmin
		},
		desired: func(ctx context.Context, fn func(rel)) error {
			last := uuid.Nil
			for {
				rows, err := r.db.Human.Query().
					Where(human.IDGT(last)).
					Where(graphstate.HoldingAdmins()...).
					Order(ent.Asc(human.FieldID)).
					Limit(r.pageSize).
					All(ctx)
				if err != nil {
					return fmt.Errorf("reading platform administrators: %w", err)
				}
				for _, h := range rows {
					fn(principalRel(platformType, platformID, spicedb.RelAdmin, h.PrincipalID))
				}
				if len(rows) < r.pageSize {
					return nil
				}
				last = rows[len(rows)-1].ID
			}
		},
		locks: func(_ context.Context, x rel) ([]string, error) {
			p, ok := subjectID(x)
			if !ok {
				return nil, nil
			}
			return []string{graphlock.Principal(p)}, nil
		},
		confirm: func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error) {
			p, ok := subjectID(x)
			if !ok {
				return false, nil
			}
			return graphstate.PlatformAdmin(ctx, tx.Client(), p)
		},
	}
}

// managers: principal:{managed}#{role}@principal:{manager} for every
// active manager relationship of an active manager.
func (r *Reconciler) managers() namespace {
	return namespace{
		name:    spicedb.TypePrincipal,
		filter:  spicedb.RelationshipFilter{ResourceType: spicedb.TypePrincipal, SubjectType: spicedb.TypePrincipal},
		manages: func(rel) bool { return true },
		desired: func(ctx context.Context, fn func(rel)) error {
			last := uuid.Nil
			for {
				rows, err := r.db.ManagerRelationship.Query().
					Where(managerrelationship.IDGT(last)).
					Where(graphstate.HoldingManagerRelationships()...).
					Order(ent.Asc(managerrelationship.FieldID)).
					Limit(r.pageSize).
					All(ctx)
				if err != nil {
					return fmt.Errorf("reading manager relationships: %w", err)
				}
				for _, m := range rows {
					fn(principalRel(spicedb.TypePrincipal, m.ManagedPrincipalID.String(), m.Role, m.ManagerPrincipalID))
				}
				if len(rows) < r.pageSize {
					return nil
				}
				last = rows[len(rows)-1].ID
			}
		},
		locks: func(_ context.Context, x rel) ([]string, error) {
			managed, manager, ok := ids(x)
			if !ok {
				return nil, nil
			}
			return []string{graphlock.Principal(managed), graphlock.Principal(manager)}, nil
		},
		confirm: func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error) {
			managed, manager, ok := ids(x)
			if !ok {
				return false, nil
			}
			return graphstate.Manager(ctx, tx.Client(), managed, manager, x.Relation)
		},
	}
}

// activePairs returns which of the (principal, organization) pairs hold a
// membership that calls for access with one of roles (any organization
// role when none is given).
func activePairs(ctx context.Context, c *ent.Client, principals, orgs []uuid.UUID, roles ...string) (map[[2]uuid.UUID]bool, error) {
	out := map[[2]uuid.UUID]bool{}
	if len(principals) == 0 {
		return out, nil
	}
	slices.SortFunc(principals, func(a, b uuid.UUID) int { return cmp.Compare(a.String(), b.String()) })
	slices.SortFunc(orgs, func(a, b uuid.UUID) int { return cmp.Compare(a.String(), b.String()) })
	rows, err := c.PrincipalMembership.Query().
		Where(
			principalmembership.PrincipalIDIn(slices.Compact(principals)...),
			principalmembership.OrganizationIDIn(slices.Compact(orgs)...),
		).
		Where(graphstate.HoldingMemberships(roles...)...).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading memberships: %w", err)
	}
	for _, m := range rows {
		out[[2]uuid.UUID{m.PrincipalID, m.OrganizationID}] = true
	}
	return out, nil
}

// appRoles: {app}_org:{org}#{role}@principal:{p} for every stored role in
// the application held through an active owner, admin or member
// membership of an active organization by an active principal.
// Collaborators hold no application roles.
func (r *Reconciler) appRoles(app string) namespace {
	facet := app + "_org"
	v, _ := r.registry.Get(app)
	roles := v.Roles()
	return namespace{
		name:   facet,
		filter: spicedb.RelationshipFilter{ResourceType: facet, SubjectType: spicedb.TypePrincipal},
		manages: func(x rel) bool {
			_, ok := roles[x.Relation]
			return ok
		},
		desired: func(ctx context.Context, fn func(rel)) error {
			last := uuid.Nil
			for {
				rows, err := r.db.AppRole.Query().
					Where(approle.IDGT(last), approle.Application(app)).
					Order(ent.Asc(approle.FieldID)).
					Limit(r.pageSize).
					All(ctx)
				if err != nil {
					return fmt.Errorf("reading application roles: %w", err)
				}
				principals, orgs := make([]uuid.UUID, 0, len(rows)), make([]uuid.UUID, 0, len(rows))
				for _, ar := range rows {
					principals, orgs = append(principals, ar.PrincipalID), append(orgs, ar.OrganizationID)
				}
				active, err := activePairs(ctx, r.db, principals, orgs, graphstate.AppRoleHolders()...)
				if err != nil {
					return err
				}
				for _, ar := range rows {
					if _, ok := roles[ar.Role]; ok && active[[2]uuid.UUID{ar.PrincipalID, ar.OrganizationID}] {
						fn(principalRel(facet, ar.OrganizationID.String(), ar.Role, ar.PrincipalID))
					}
				}
				if len(rows) < r.pageSize {
					return nil
				}
				last = rows[len(rows)-1].ID
			}
		},
		locks: orgPrincipalLocks,
		confirm: func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error) {
			org, p, ok := ids(x)
			if !ok {
				return false, nil
			}
			return graphstate.AppRole(ctx, tx.Client(), org, p, app, x.Relation)
		},
	}
}

// grants: {type}:{id}#{role}@principal:{p} for every grant on the
// resource type held through an active membership of an active
// organization by an active principal.
func (r *Reconciler) grants(resourceType string) namespace {
	return namespace{
		name:   resourceType,
		filter: spicedb.RelationshipFilter{ResourceType: resourceType, SubjectType: spicedb.TypePrincipal},
		manages: func(x rel) bool {
			return authz.ValidResourceRole(x.Relation)
		},
		desired: func(ctx context.Context, fn func(rel)) error {
			last := uuid.Nil
			for {
				rows, err := r.db.ResourceGrant.Query().
					Where(resourcegrant.IDGT(last), resourcegrant.ResourceType(resourceType)).
					Order(ent.Asc(resourcegrant.FieldID)).
					Limit(r.pageSize).
					All(ctx)
				if err != nil {
					return fmt.Errorf("reading resource grants: %w", err)
				}
				principals, orgs := make([]uuid.UUID, 0, len(rows)), make([]uuid.UUID, 0, len(rows))
				for _, g := range rows {
					principals, orgs = append(principals, g.PrincipalID), append(orgs, g.OrganizationID)
				}
				active, err := activePairs(ctx, r.db, principals, orgs)
				if err != nil {
					return err
				}
				for _, g := range rows {
					if authz.ValidResourceRole(g.Role) && active[[2]uuid.UUID{g.PrincipalID, g.OrganizationID}] {
						fn(principalRel(resourceType, g.ResourceID, g.Role, g.PrincipalID))
					}
				}
				if len(rows) < r.pageSize {
					return nil
				}
				last = rows[len(rows)-1].ID
			}
		},
		locks: func(ctx context.Context, x rel) ([]string, error) {
			p, ok := subjectID(x)
			if !ok {
				return nil, nil
			}
			keys := []string{graphlock.Principal(p)}
			// The grant names the organization; it is read again under
			// the locks.
			g, err := r.db.ResourceGrant.Query().
				Where(resourcegrant.PrincipalID(p), resourcegrant.ResourceType(x.ResourceType), resourcegrant.ResourceID(x.ResourceID)).
				Only(ctx)
			switch {
			case ent.IsNotFound(err):
			case err != nil:
				return nil, fmt.Errorf("reading resource grant: %w", err)
			default:
				keys = append(keys, graphlock.Organization(g.OrganizationID))
			}
			return keys, nil
		},
		confirm: func(ctx context.Context, tx *ent.Tx, x rel, keys []string) (bool, error) {
			p, ok := subjectID(x)
			if !ok {
				return false, nil
			}
			g, err := tx.ResourceGrant.Query().
				Where(resourcegrant.PrincipalID(p), resourcegrant.ResourceType(x.ResourceType), resourcegrant.ResourceID(x.ResourceID)).
				Only(ctx)
			if ent.IsNotFound(err) {
				return false, nil
			}
			if err != nil {
				return false, fmt.Errorf("reading resource grant: %w", err)
			}
			// A grant created after the locks were chosen is left to the
			// next run, which locks its organization.
			if g.Role != x.Relation || !slices.Contains(keys, graphlock.Organization(g.OrganizationID)) {
				return false, nil
			}
			return graphstate.Membership(ctx, tx.Client(), g.OrganizationID, p)
		},
	}
}
