package authz

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
)

// Resource roles are the standard ladder a resource type that accepts
// collaborators uses (ADR-008). Their names are reserved so that every
// application means the same thing by them; each role includes the ones
// below it. They are distinct from organization roles and from an
// application's own roles.
const (
	// ResourceRoleViewer reads the resource.
	ResourceRoleViewer = "viewer"
	// ResourceRoleContributor also changes the resource and creates items
	// within it.
	ResourceRoleContributor = "contributor"
	// ResourceRoleMaintainer also manages the resource's settings and its
	// collaborators.
	ResourceRoleMaintainer = "maintainer"
)

// Resource permissions of the ladder. A resource definition exposes them
// under these names, and both providers answer them: Can(principal,
// PermResourceView, resource), and ListResources with one of them.
const (
	PermResourceView   Action = "view"
	PermResourceEdit   Action = "edit"
	PermResourceManage Action = "manage"
)

// resourceRoles lists the resource roles, lowest first.
var resourceRoles = []string{ResourceRoleViewer, ResourceRoleContributor, ResourceRoleMaintainer}

// ResourceRolePermissions maps each resource role to the permissions it
// grants on the resource, mirroring the relations of a collaborator-able
// resource definition (see ResourceRoleFragment). A test keeps the two
// equal.
var ResourceRolePermissions = map[string][]Action{
	ResourceRoleViewer:      {PermResourceView},
	ResourceRoleContributor: {PermResourceView, PermResourceEdit},
	ResourceRoleMaintainer:  {PermResourceView, PermResourceEdit, PermResourceManage},
}

// ResourceRoles returns the resource roles, lowest first.
func ResourceRoles() []string { return slices.Clone(resourceRoles) }

// ValidResourceRole reports whether role is a resource role.
func ValidResourceRole(role string) bool { return slices.Contains(resourceRoles, role) }

// ResourceRoleRank orders the resource roles: viewer 1, contributor 2,
// maintainer 3, and 0 for anything else.
func ResourceRoleRank(role string) int { return slices.Index(resourceRoles, role) + 1 }

// ResourceRoleAllows reports whether a resource role grants a permission.
func ResourceRoleAllows(role string, action Action) bool {
	return slices.Contains(ResourceRolePermissions[role], action)
}

// IsResourcePermission reports whether action is one of the ladder's
// permissions.
func IsResourcePermission(action Action) bool {
	return ResourceRoleAllows(ResourceRoleMaintainer, action)
}

// ResourceRolesGranting returns the resource roles that grant action,
// lowest first.
func ResourceRolesGranting(action Action) []string {
	var out []string
	for _, r := range resourceRoles {
		if ResourceRoleAllows(r, action) {
			out = append(out, r)
		}
	}
	return out
}

// ResourceRoleFragment returns the standard SpiceDB definition of a
// resource type that accepts collaborators: the three ladder relations
// bound to principal, an org relation to the organization, and the view,
// edit and manage permissions. resourceType is "{app}_{type}".
func ResourceRoleFragment(resourceType string) string {
	return fmt.Sprintf(`definition %s {
    relation org: organization
    relation viewer: principal
    relation contributor: principal
    relation maintainer: principal

    permission view   = viewer + contributor + maintainer + org->view
    permission edit   = contributor + maintainer + org->edit
    permission manage = maintainer + org->manage
}
`, resourceType)
}

// ResourceRef identifies one resource of an organization. The identifier
// is the application's own string, so the substrate stores grants for
// resources it knows nothing else about.
type ResourceRef struct {
	// Type is the definition name, "{app}_{type}", as declared in the
	// application's vocabulary.
	Type string
	// ID is the application's identifier of the resource.
	ID string
	// OrganizationID is the organization that owns the resource. Reads may
	// leave it zero to mean the organization the grant was made in.
	OrganizationID uuid.UUID
}

// ResourceRefOf returns the reference for a Resource with an ID. The
// organization is Resource.OrgID when set.
func ResourceRefOf(r Resource) (ResourceRef, bool) {
	if r.ID == nil {
		return ResourceRef{}, false
	}
	ref := ResourceRef{Type: string(r.Type), ID: r.ID.String()}
	if r.OrgID != nil {
		ref.OrganizationID = *r.OrgID
	}
	return ref, true
}

// Grant is a principal's role on one resource.
type Grant struct {
	PrincipalID uuid.UUID
	Resource    ResourceRef
	// Role is a resource role.
	Role string
	// GrantedBy is the principal who made the grant, when known.
	GrantedBy *uuid.UUID
}

// ResourceSet is the answer to ListResources: the resources a principal
// holds a permission on, in two parts so that an application can apply
// them as `org_id IN (OrganizationIDs) OR id IN (IDs)`.
type ResourceSet struct {
	// IDs are resources the principal holds the permission on directly,
	// through a grant, or, in the relationship-based mode, through any
	// relationship the schema expresses.
	IDs []string
	// OrganizationIDs are organizations in which the principal's
	// organization role grants the permission on every resource of the
	// type. The relationship-based provider leaves it empty: its lookup
	// already returns each resource in IDs.
	OrganizationIDs []uuid.UUID
}

// Errors of the resource-grant operations.
var (
	// ErrInvalidResourceRole means a role is not viewer, contributor or
	// maintainer.
	ErrInvalidResourceRole = errors.New("authz: invalid resource role")
	// ErrInvalidResource means a resource reference is malformed or names a
	// resource type that does not accept collaborators.
	ErrInvalidResource = errors.New("authz: invalid resource")
	// ErrGrantNotFound means the principal holds no grant on the resource.
	ErrGrantNotFound = errors.New("authz: resource grant not found")
	// ErrResourceOrganizationMismatch means the resource is already
	// granted in a different organization. A resource does not move
	// between organizations through a grant; the application moves its
	// grants with it.
	ErrResourceOrganizationMismatch = errors.New("authz: resource belongs to another organization")
)

// ResourceGranter is the grant half of the platform contract (ADR-008),
// implemented with the same semantics by the role-based and the
// relationship-based providers and checked by the providertest suite.
//
// Granting to a principal with no membership in the resource's
// organization adds a collaborator membership; revoking the last grant of
// a collaborator removes it. A grant to a lower role than the principal
// held, and a revoke, record an access change.
type ResourceGranter interface {
	// GrantResourceRole gives the principal a role on the resource,
	// replacing any role it held there. grantedBy is the principal making
	// the grant; the zero UUID records none.
	GrantResourceRole(ctx context.Context, principalID uuid.UUID, resource ResourceRef, role string, grantedBy uuid.UUID) error

	// RevokeResourceRole removes the principal's grant on the resource.
	// It returns ErrGrantNotFound when there is none.
	RevokeResourceRole(ctx context.Context, principalID uuid.UUID, resource ResourceRef) error

	// ListResourceGrants lists the grants on one resource, highest role
	// first.
	ListResourceGrants(ctx context.Context, resource ResourceRef) ([]Grant, error)

	// ListResources returns the resources of resourceType on which the
	// principal holds permission (view, edit or manage). An application
	// uses the result to constrain queries and row-level security, in
	// addition to checking each request.
	ListResources(ctx context.Context, principalID uuid.UUID, resourceType string, permission Action) (ResourceSet, error)
}

// ResourceGrantReader is what the role-based provider reads at check time.
// The Ent-backed grant service implements it next to ResourceGranter.
type ResourceGrantReader interface {
	// ResourceRole returns the resource role the principal holds on the
	// resource through an active membership, or "".
	ResourceRole(ctx context.Context, principalID uuid.UUID, resource ResourceRef) (string, error)

	// OrganizationRoles returns the principal's role in each organization
	// where it has an active membership.
	OrganizationRoles(ctx context.Context, principalID uuid.UUID) (map[uuid.UUID]string, error)
}

// ResourceGrantSyncer is implemented by a RelationshipSyncer that also
// writes resource grants to the authorization graph. Like AppRoleSyncer it
// is a separate interface so existing syncers keep compiling; callers
// type-assert and skip grants when it is not implemented.
type ResourceGrantSyncer interface {
	// SetResourceGrant records that the principal holds role on the
	// resource, replacing any other role it held there in one write.
	SetResourceGrant(ctx context.Context, principalID uuid.UUID, resource ResourceRef, role string) error

	// RemoveResourceGrant removes every role the principal holds on the
	// resource.
	RemoveResourceGrant(ctx context.Context, principalID uuid.UUID, resource ResourceRef) error
}

var (
	resourceIDRe   = regexp.MustCompile(`^[a-zA-Z0-9/_|\-=+]+$`)
	resourceTypeRe = regexp.MustCompile(`^([a-z][a-z0-9]{1,31})_([a-z][a-z0-9_]*)$`)
)

// ValidateResourceRef checks the shape of a resource reference: a type of
// the form "{app}_{type}" with a valid application identifier, a
// non-empty identifier in the character set SpiceDB object identifiers
// allow (so both modes accept the same resources), and an organization.
func ValidateResourceRef(ref ResourceRef) error {
	if len(ref.Type) > 128 || !resourceTypeRe.MatchString(ref.Type) {
		return fmt.Errorf("%w: type %q is not {app}_{type}", ErrInvalidResource, ref.Type)
	}
	if len(ref.ID) > 1024 || !resourceIDRe.MatchString(ref.ID) {
		return fmt.Errorf("%w: id %q must be 1 to 1024 characters of letters, digits and /_|-=+", ErrInvalidResource, ref.ID)
	}
	if ref.OrganizationID == uuid.Nil {
		return fmt.Errorf("%w: organization is required", ErrInvalidResource)
	}
	return nil
}

// ResourceApp returns the application identifier of a resource type
// "{app}_{type}", or "" when it has none.
func ResourceApp(resourceType string) string {
	m := resourceTypeRe.FindStringSubmatch(resourceType)
	if m == nil {
		return ""
	}
	return m[1]
}

// ValidateResourceType checks that resourceType may be granted on: its
// "{app}_" prefix names a vocabulary in the registry, and, when that
// vocabulary carries a SpiceDB fragment, the fragment declares the type
// with the whole resource-role ladder (CollaboratorDefinitions). A
// vocabulary with no fragment supports only the role-based provider, where
// any type of the application can be granted on.
func (r *VocabularyRegistry) ValidateResourceType(resourceType string) error {
	app := ResourceApp(resourceType)
	if app == "" || !strings.HasPrefix(resourceType, app+"_") {
		return fmt.Errorf("%w: type %q is not {app}_{type}", ErrInvalidResource, resourceType)
	}
	v, ok := r.Get(app)
	if !ok {
		return fmt.Errorf("%w: application %q of type %q is not registered", ErrInvalidResource, app, resourceType)
	}
	fragment := v.SpiceDBSchema()
	if strings.TrimSpace(fragment) == "" {
		return nil
	}
	if !slices.Contains(CollaboratorDefinitions(fragment), resourceType) {
		return fmt.Errorf("%w: %q does not accept collaborators: its definition in the %q fragment must declare viewer, contributor and maintainer", ErrInvalidResource, resourceType, app)
	}
	return nil
}

// CollaboratorResourceTypes returns the resource types of an application
// that accept collaborators according to its SpiceDB fragment, sorted. It
// is empty for an unregistered application or one with no fragment.
func (r *VocabularyRegistry) CollaboratorResourceTypes(app string) []string {
	v, ok := r.Get(app)
	if !ok {
		return nil
	}
	types := CollaboratorDefinitions(v.SpiceDBSchema())
	slices.Sort(types)
	return types
}
