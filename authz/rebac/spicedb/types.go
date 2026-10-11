// Package spicedb provides SpiceDB-based authorization for SystemForge.
package spicedb

// CheckRequest represents a permission check request.
type CheckRequest struct {
	// ResourceType is the type of the resource (e.g., "organization", "project")
	ResourceType string
	// ResourceID is the ID of the resource
	ResourceID string
	// Permission is the permission to check (e.g., "view", "edit", "manage")
	Permission string
	// SubjectType is the type of the subject (e.g., "principal", "user")
	SubjectType string
	// SubjectID is the ID of the subject
	SubjectID string
}

// Relationship represents a relationship tuple.
type Relationship struct {
	// ResourceType is the type of the resource
	ResourceType string
	// ResourceID is the ID of the resource
	ResourceID string
	// Relation is the relationship type (e.g., "owner", "member", "admin")
	Relation string
	// SubjectType is the type of the subject
	SubjectType string
	// SubjectID is the ID of the subject
	SubjectID string
}

// LookupSubjectsRequest represents a request to find subjects with a permission.
type LookupSubjectsRequest struct {
	// ResourceType is the type of the resource
	ResourceType string
	// ResourceID is the ID of the resource
	ResourceID string
	// Permission is the permission to check
	Permission string
	// SubjectType is the type of subjects to look up
	SubjectType string
}

// LookupResourcesRequest represents a request to find resources a subject can access.
type LookupResourcesRequest struct {
	// ResourceType is the type of resources to look up
	ResourceType string
	// Permission is the permission to check
	Permission string
	// SubjectType is the type of the subject
	SubjectType string
	// SubjectID is the ID of the subject
	SubjectID string
}

// Common resource type constants.
const (
	// TypePrincipal represents a principal (user, service, agent).
	TypePrincipal = "principal"

	// TypeOrganization represents an organization.
	TypeOrganization = "organization"

	// TypeUser represents a user.
	TypeUser = "user"
)

// Common permission constants.
const (
	// PermView allows viewing a resource.
	PermView = "view"

	// PermList lets a principal see that an organization exists: every
	// membership grants it, collaborators included.
	PermList = "list"

	// PermEdit allows editing a resource.
	PermEdit = "edit"

	// PermManage allows managing a resource (admin operations).
	PermManage = "manage"

	// PermDelete allows deleting a resource.
	PermDelete = "delete"

	// PermCreate allows creating resources.
	PermCreate = "create"
)

// Common relation constants.
const (
	// RelOwner represents the owner relation.
	RelOwner = "owner"

	// RelAdmin represents the admin relation.
	RelAdmin = "admin"

	// RelMember represents the member relation.
	RelMember = "member"

	// RelCollaborator represents the organization collaborator relation: a
	// principal with access to individual resources only (ADR-008).
	RelCollaborator = "collaborator"
)

// Resource-role relations of a collaborator-able resource definition
// (ADR-008), lowest first.
const (
	// RelViewer reads the resource.
	RelViewer = "viewer"

	// RelContributor also changes the resource and creates items in it.
	RelContributor = "contributor"

	// RelMaintainer also manages the resource's settings and collaborators.
	RelMaintainer = "maintainer"
)

// orgRoles are the organization relations of the base schema, highest
// privilege first.
var orgRoles = []string{RelOwner, RelAdmin, RelMember, RelCollaborator}
