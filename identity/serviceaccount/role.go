package serviceaccount

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/approle"
)

// GrantRole gives the account a role in an application of its
// organization, replacing the role it held there.
func (s *Service) GrantRole(ctx context.Context, id uuid.UUID, application, role string, by uuid.UUID) error {
	acct, err := s.requireRoles(ctx, id)
	if err != nil {
		return err
	}
	in := approle.AssignInput{
		OrganizationID: acct.OrganizationID,
		PrincipalID:    id,
		Application:    application,
		Role:           role,
		AssignedBy:     by,
	}
	_, err = s.roles.Assign(ctx, in)
	if errors.Is(err, approle.ErrAlreadyAssigned) {
		_, err = s.roles.Change(ctx, in)
	}
	if err != nil {
		return err
	}
	s.emit(ctx, "role_granted", by, id, map[string]any{"application": application, "role": role, "organization_id": acct.OrganizationID.String()})
	return nil
}

// RemoveRole removes the account's role in an application, which records
// an AppRoleChanged access change.
func (s *Service) RemoveRole(ctx context.Context, id uuid.UUID, application string, by uuid.UUID) error {
	acct, err := s.requireRoles(ctx, id)
	if err != nil {
		return err
	}
	if err := s.roles.Remove(ctx, acct.OrganizationID, id, application, by); err != nil {
		return err
	}
	s.emit(ctx, "role_removed", by, id, map[string]any{"application": application, "organization_id": acct.OrganizationID.String()})
	return nil
}

// requireRoles returns the account, or an error when it does not exist or
// the service has no application role service.
func (s *Service) requireRoles(ctx context.Context, id uuid.UUID) (*Account, error) {
	if s.roles == nil {
		return nil, errors.New("serviceaccount: application roles need Config.Roles")
	}
	return s.Get(ctx, id)
}
