// Package spicedb is the former import path of the SpiceDB engine for
// relationship-based authorization.
//
// Deprecated: use github.com/plexusone/systemforge/authz/rebac/spicedb. The
// engine is unchanged; only the path moved, so that the authorization modes
// are named for what they evaluate (rbac, rebac) with the engine beneath
// its mode. This package forwards to the new one and will be removed in the
// next major release. Only what existed under this path is forwarded;
// resource grants and later additions are in authz/rebac/spicedb.
package spicedb

import (
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/rebac/spicedb"
)

// Deprecated: use the rebac/spicedb package.
type (
	CheckRequest           = spicedb.CheckRequest
	Client                 = spicedb.Client
	Config                 = spicedb.Config
	LookupResourcesRequest = spicedb.LookupResourcesRequest
	LookupSubjectsRequest  = spicedb.LookupSubjectsRequest
	Provider               = spicedb.Provider
	Relationship           = spicedb.Relationship
	RelationshipFilter     = spicedb.RelationshipFilter
	Syncer                 = spicedb.Syncer
)

// BaseSchema is the base SpiceDB schema.
//
// Deprecated: use authz.BaseSpiceDBSchema, or compose a deployment schema
// with authz.VocabularyRegistry.ComposeSpiceDBSchema.
const BaseSchema = authz.BaseSpiceDBSchema

// Deprecated: use the rebac/spicedb package.
const (
	TypePrincipal    = spicedb.TypePrincipal
	TypeOrganization = spicedb.TypeOrganization
	TypeUser         = spicedb.TypeUser
	PermView         = spicedb.PermView
	PermEdit         = spicedb.PermEdit
	PermManage       = spicedb.PermManage
	PermDelete       = spicedb.PermDelete
	PermCreate       = spicedb.PermCreate
	RelOwner         = spicedb.RelOwner
	RelAdmin         = spicedb.RelAdmin
	RelMember        = spicedb.RelMember
	RelCollaborator  = spicedb.RelCollaborator
	RelViewer        = spicedb.RelViewer
	RelContributor   = spicedb.RelContributor
	RelMaintainer    = spicedb.RelMaintainer
	PermList         = spicedb.PermList
)

// Deprecated: use the rebac/spicedb package.
var (
	NewClient      = spicedb.NewClient
	NewProvider    = spicedb.NewProvider
	NewSyncer      = spicedb.NewSyncer
	DefaultConfig  = spicedb.DefaultConfig
	ResourceSchema = spicedb.ResourceSchema
)
