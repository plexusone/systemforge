// Package authzguardsql builds GuardSQL policies from SystemForge
// authorization. PolicyBuilder checks read on every entity and read, list
// and sort on every field of a GuardSQL schema, and compiles the answers
// into a guardsql.Policy. Entities and fields are mapped to resources by a
// ResourceBuilder; DefaultResourceBuilder gives each one a concrete,
// organization-scoped resource ID.
package authzguardsql

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/grokify/guardsql"
	gqlauthz "github.com/grokify/guardsql/authz"
	"github.com/plexusone/systemforge/authz"
)

// ResourceBuilder maps GuardSQL entities and fields to SystemForge resources.
// Applications can use these names directly in SpiceDB schemas or adapt them to
// product-specific resource types.
type ResourceBuilder interface {
	EntityResource(entity string) authz.Resource
	FieldResource(entity, field string) authz.Resource
}

// ResourceBuilderFunc adapts functions into a ResourceBuilder.
type ResourceBuilderFunc struct {
	Entity func(entity string) authz.Resource
	Field  func(entity, field string) authz.Resource
}

// EntityResource implements ResourceBuilder.
func (f ResourceBuilderFunc) EntityResource(entity string) authz.Resource {
	if f.Entity != nil {
		return f.Entity(entity)
	}
	return DefaultResourceBuilder{}.EntityResource(entity)
}

// FieldResource implements ResourceBuilder.
func (f ResourceBuilderFunc) FieldResource(entity, field string) authz.Resource {
	if f.Field != nil {
		return f.Field(entity, field)
	}
	return DefaultResourceBuilder{}.FieldResource(entity, field)
}

// Resource types produced by DefaultResourceBuilder.
const (
	ResourceTypeEntity authz.ResourceType = "guardsql_entity"
	ResourceTypeField  authz.ResourceType = "guardsql_field"
)

// resourceIDNamespace is the UUID namespace of the deterministic entity and
// field resource IDs.
var resourceIDNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://github.com/plexusone/systemforge/authzguardsql"))

// DefaultResourceBuilder maps every entity and every field to its own
// concrete resource: type ResourceTypeEntity or ResourceTypeField, with a
// deterministic ID derived from the organization, entity and field names
// (see EntityResourceID and FieldResourceID), and the organization as the
// resource's OrgID. The names are also kept in the "entity" and "field"
// attributes for logging, but no provider evaluates attributes.
//
// Policy follows from the provider:
//
//   - SpiceDB checks the concrete object, so each field has its own
//     relationships; write them for guardsql_field:<FieldResourceID>.
//   - rbac checks role permissions keyed by type ("guardsql_field.read"),
//     so such a permission grants every field of every entity. For
//     column-level policy with rbac, use a ResourceBuilder whose resource
//     types name the entity and field.
//
// Set OrgID: without it, rbac answers only for the resource owner, and IDs
// are shared by every organization.
type DefaultResourceBuilder struct {
	// OrgID is the organization the schema's data belongs to.
	OrgID *uuid.UUID
}

// EntityResourceID returns the deterministic resource ID of entity.
func (b DefaultResourceBuilder) EntityResourceID(entity string) uuid.UUID {
	return uuid.NewSHA1(resourceIDNamespace, []byte(b.scope()+"\x00entity\x00"+strings.ToLower(entity)))
}

// FieldResourceID returns the deterministic resource ID of entity's field.
func (b DefaultResourceBuilder) FieldResourceID(entity, field string) uuid.UUID {
	return uuid.NewSHA1(resourceIDNamespace, []byte(b.scope()+"\x00field\x00"+strings.ToLower(entity)+"\x00"+strings.ToLower(field)))
}

// scope returns the organization part of the resource IDs.
func (b DefaultResourceBuilder) scope() string {
	if b.OrgID == nil {
		return ""
	}
	return b.OrgID.String()
}

// withOrg sets the builder's organization on r.
func (b DefaultResourceBuilder) withOrg(r authz.Resource) authz.Resource {
	if b.OrgID != nil {
		r = r.WithOrg(*b.OrgID)
	}
	return r
}

// EntityResource implements ResourceBuilder.
func (b DefaultResourceBuilder) EntityResource(entity string) authz.Resource {
	return b.withOrg(authz.NewResourceWithID(ResourceTypeEntity, b.EntityResourceID(entity))).
		WithAttr("entity", strings.ToLower(entity))
}

// FieldResource implements ResourceBuilder.
func (b DefaultResourceBuilder) FieldResource(entity, field string) authz.Resource {
	return b.withOrg(authz.NewResourceWithID(ResourceTypeField, b.FieldResourceID(entity, field))).
		WithAttr("entity", strings.ToLower(entity)).
		WithAttr("field", strings.ToLower(field))
}

// ErrNoAuthorizedEntities is returned by PolicyBuilder.Build when the
// principal may read no entity of the schema. A policy with nothing allowed
// must not be built, because guardsql reads empty allowlists as unrestricted.
var ErrNoAuthorizedEntities = errors.New("authzguardsql: principal may read no entity")

// PolicyBuilder checks SystemForge authorization for schema entities/fields and
// compiles the result into a GuardSQL policy.
type PolicyBuilder struct {
	Authorizer      authz.Authorizer
	Principal       authz.Principal
	Schema          guardsql.Schema
	ResourceBuilder ResourceBuilder
	RequireLimit    bool
	MaxLimit        int
	MaxDepth        int
	MaxNodes        int
	MaxInValues     int
	AllowStar       bool
}

// Build returns a read-only GuardSQL policy derived from SystemForge authz.
// It returns ErrNoAuthorizedEntities when the principal may read no entity;
// callers should refuse the query.
func (b PolicyBuilder) Build(ctx context.Context) (guardsql.Policy, error) {
	if b.Authorizer == nil {
		return guardsql.Policy{}, fmt.Errorf("authorizer is required")
	}
	builder := b.ResourceBuilder
	if builder == nil {
		builder = DefaultResourceBuilder{}
	}
	decision := gqlauthz.Decision{
		Fields:       map[string]map[string]guardsql.FieldPolicy{},
		RequireLimit: b.RequireLimit,
		MaxLimit:     b.MaxLimit,
		MaxDepth:     b.MaxDepth,
		MaxNodes:     b.MaxNodes,
		MaxInValues:  b.MaxInValues,
		AllowStar:    b.AllowStar,
	}
	schema := b.Schema.Normalize()
	for entityName, entity := range schema.Entities {
		canReadEntity, err := b.Authorizer.Can(ctx, b.Principal, authz.ActionRead, builder.EntityResource(entityName))
		if err != nil {
			return guardsql.Policy{}, err
		}
		if !canReadEntity {
			continue
		}
		decision.AllowedEntities = append(decision.AllowedEntities, entityName)
		fieldPolicies := map[string]guardsql.FieldPolicy{}
		for fieldName := range entity.Fields {
			fieldResource := builder.FieldResource(entityName, fieldName)
			selectable, err := b.Authorizer.Can(ctx, b.Principal, authz.ActionRead, fieldResource)
			if err != nil {
				return guardsql.Policy{}, err
			}
			filterable, err := b.Authorizer.Can(ctx, b.Principal, authz.ActionList, fieldResource)
			if err != nil {
				return guardsql.Policy{}, err
			}
			sortable, err := b.Authorizer.Can(ctx, b.Principal, authz.Action("sort"), fieldResource)
			if err != nil {
				return guardsql.Policy{}, err
			}
			if selectable || filterable || sortable {
				fieldPolicies[fieldName] = guardsql.FieldPolicy{
					Selectable: selectable,
					Filterable: filterable,
					Sortable:   sortable,
				}
			}
		}
		decision.Fields[entityName] = fieldPolicies
	}
	if len(decision.AllowedEntities) == 0 {
		return guardsql.Policy{}, ErrNoAuthorizedEntities
	}
	return gqlauthz.PolicyFromDecision(decision), nil
}
