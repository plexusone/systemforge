package managedprincipal

import (
	"context"
	"fmt"
	"slices"

	entsql "entgo.io/ent/dialect/sql"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/managerrelationship"
	"github.com/plexusone/systemforge/identity/ent/predicate"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
)

// MaxListLimit bounds a page of ListManagedBy.
const MaxListLimit = 200

// ManagedSummary is a managed principal as one of its managers lists it.
type ManagedSummary struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	DisplayName string    `json:"display_name"`
	// Roles are the roles the listing manager holds over the principal.
	Roles []string `json:"roles"`
}

// ListManagedBy returns the active principals that managerID actively
// manages, ordered by principal ID, starting after the given ID (uuid.Nil
// for the first page). limit is clamped to 1..MaxListLimit. A manager only
// ever sees its own relationships, so the listing needs no further
// permission.
func (s *Service) ListManagedBy(ctx context.Context, managerID, after uuid.UUID, limit int) ([]ManagedSummary, error) {
	if limit <= 0 || limit > MaxListLimit {
		limit = MaxListLimit
	}
	q := s.client.ManagerRelationship.Query().
		Where(
			managerrelationship.ManagerPrincipalID(managerID),
			managerrelationship.Active(true),
			managerrelationship.HasManagedWith(entprincipal.Active(true)),
		)
	if after != uuid.Nil {
		q = q.Where(predicate.ManagerRelationship(entsql.FieldGT(managerrelationship.FieldManagedPrincipalID, after)))
	}
	// A principal managed in several roles has a row for each, so read
	// enough rows for a full page of principals.
	rows, err := q.
		WithManaged().
		Order(ent.Asc(managerrelationship.FieldManagedPrincipalID), ent.Asc(managerrelationship.FieldRole)).
		Limit(limit * len(s.roles)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("managedprincipal: list managed principals: %w", err)
	}
	out := make([]ManagedSummary, 0, limit)
	for _, r := range rows {
		if n := len(out); n > 0 && out[n-1].PrincipalID == r.ManagedPrincipalID {
			if !slices.Contains(out[n-1].Roles, r.Role) {
				out[n-1].Roles = append(out[n-1].Roles, r.Role)
			}
			continue
		}
		if len(out) == limit {
			break
		}
		sum := ManagedSummary{PrincipalID: r.ManagedPrincipalID, Roles: []string{r.Role}}
		if r.Edges.Managed != nil {
			sum.DisplayName = r.Edges.Managed.DisplayName
		}
		out = append(out, sum)
	}
	return out, nil
}
