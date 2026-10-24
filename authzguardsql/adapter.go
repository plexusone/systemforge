package authzguardsql

import (
	"context"
	"errors"
	"fmt"
	"strings"

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

// DefaultResourceBuilder uses stable resource type names suitable for examples.
type DefaultResourceBuilder struct{}

// EntityResource implements ResourceBuilder.
func (DefaultResourceBuilder) EntityResource(entity string) authz.Resource {
	return authz.NewResource(authz.ResourceType("guardsql_entity")).WithAttr("entity", strings.ToLower(entity))
}

// FieldResource implements ResourceBuilder.
func (DefaultResourceBuilder) FieldResource(entity, field string) authz.Resource {
	return authz.NewResource(authz.ResourceType("guardsql_field")).
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
