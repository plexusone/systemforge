package serviceaccount

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/ent"
	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/organization"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/ent/principalmembership"
	"github.com/plexusone/systemforge/identity/ent/serviceprincipal"
	"github.com/plexusone/systemforge/identity/principal"
)

// Create creates a service account in an active, non-personal
// organization: the service principal, its ServicePrincipal row recording
// who created it, and its service_account membership, in one transaction.
//
// The membership is not written to the authorization graph: applications
// see the account through its application roles and the orgs claim.
func (s *Service) Create(ctx context.Context, in CreateInput) (*Account, error) {
	if in.Name == "" {
		return nil, ErrNameRequired
	}
	if err := s.requireOrganization(ctx, in.OrganizationID); err != nil {
		return nil, err
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("serviceaccount: starting transaction: %w", err)
	}
	p, afterCommit, err := s.insert(ctx, tx, in)
	if err != nil {
		return nil, errors.Join(err, tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("serviceaccount: committing: %w", err)
	}
	if err := afterCommit(ctx); err != nil {
		return nil, err
	}
	s.logger.InfoContext(ctx, "service account created",
		"principal_id", p.ID, "identifier", p.Identifier, "organization_id", in.OrganizationID, "created_by", in.CreatedBy)
	s.emit(ctx, "created", in.CreatedBy, p.ID, map[string]any{"identifier": p.Identifier, "organization_id": in.OrganizationID.String()})
	return s.Get(ctx, p.ID)
}

// insert writes the principal, its service row and its membership in tx.
func (s *Service) insert(ctx context.Context, tx *ent.Tx, in CreateInput) (*principal.Principal, principal.AfterCommit, error) {
	input := principal.CreateServiceInput{
		Identifier:     NewIdentifier(),
		DisplayName:    in.Name,
		ServiceType:    ServiceType,
		OrganizationID: &in.OrganizationID,
		AllowedScopes:  in.Scopes,
	}
	if in.Description != "" {
		input.Description = &in.Description
	}
	if in.CreatedBy != uuid.Nil {
		input.CreatedBy = &in.CreatedBy
	}
	p, afterCommit, err := s.principals.CreateServiceInTx(ctx, tx, input)
	if err != nil {
		return nil, nil, err
	}
	if _, err := tx.PrincipalMembership.Create().
		SetPrincipalID(p.ID).
		SetOrganizationID(in.OrganizationID).
		SetRole(MembershipRole).
		SetActive(true).
		Save(ctx); err != nil {
		return nil, nil, fmt.Errorf("serviceaccount: creating membership: %w", err)
	}
	return p, afterCommit, nil
}

// requireOrganization returns an error unless the organization exists, is
// active and is not personal.
func (s *Service) requireOrganization(ctx context.Context, id uuid.UUID) error {
	org, err := s.client.Organization.Get(ctx, id)
	if ent.IsNotFound(err) {
		return fmt.Errorf("%w: %s", ErrOrganizationNotFound, id)
	}
	if err != nil {
		return fmt.Errorf("serviceaccount: reading organization: %w", err)
	}
	if !org.Active {
		return fmt.Errorf("%w: %s", ErrOrganizationInactive, id)
	}
	if org.OrgType == organization.OrgTypePersonal {
		return fmt.Errorf("%w: %s", ErrPersonalOrganization, id)
	}
	return nil
}

// accountQuery selects service accounts.
func (s *Service) accountQuery() *ent.PrincipalQuery {
	return s.client.Principal.Query().
		Where(
			entprincipal.TypeEQ(entprincipal.TypeService),
			entprincipal.OrganizationIDNotNil(),
			entprincipal.HasServicePrincipalWith(serviceprincipal.ServiceTypeEQ(ServiceType)),
		).
		WithServicePrincipal()
}

// Get returns a service account.
func (s *Service) Get(ctx context.Context, id uuid.UUID) (*Account, error) {
	p, err := s.accountQuery().Where(entprincipal.ID(id)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("serviceaccount: reading account: %w", err)
	}
	return toAccount(p), nil
}

// List returns the organization's service accounts, oldest first.
func (s *Service) List(ctx context.Context, organizationID uuid.UUID) ([]*Account, error) {
	rows, err := s.accountQuery().
		Where(entprincipal.OrganizationID(organizationID)).
		Order(ent.Asc(entprincipal.FieldCreatedAt), ent.Asc(entprincipal.FieldID)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("serviceaccount: listing accounts: %w", err)
	}
	out := make([]*Account, len(rows))
	for i, p := range rows {
		out[i] = toAccount(p)
	}
	return out, nil
}

// Disable deactivates the account, which records a Deactivated access
// change: its tokens stop at once in applications with a revocation cache,
// and no new token is issued.
func (s *Service) Disable(ctx context.Context, id, by uuid.UUID) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	if err := s.principals.Deactivate(ctx, id); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "service account disabled", "principal_id", id, "by", by)
	s.emit(ctx, "disabled", by, id, nil)
	return nil
}

// Enable reactivates a disabled account.
func (s *Service) Enable(ctx context.Context, id, by uuid.UUID) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	if err := s.principals.Reactivate(ctx, id); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "service account enabled", "principal_id", id, "by", by)
	s.emit(ctx, "enabled", by, id, nil)
	return nil
}

// Delete deactivates the account (recording Deactivated if it was
// active), removes its application roles, then deletes its keys,
// membership and principal.
func (s *Service) Delete(ctx context.Context, id, by uuid.UUID) error {
	acct, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if s.roles == nil {
		return errors.New("serviceaccount: deleting an account needs Config.Roles")
	}
	if acct.Active {
		if err := s.principals.Deactivate(ctx, id); err != nil {
			return err
		}
	}
	if _, err := s.roles.RemoveForMember(ctx, acct.OrganizationID, id); err != nil {
		return err
	}
	if err := s.deleteRows(ctx, id); err != nil {
		return err
	}
	s.logger.InfoContext(ctx, "service account deleted", "principal_id", id, "identifier", acct.Identifier, "by", by)
	s.emit(ctx, "deleted", by, id, map[string]any{"identifier": acct.Identifier})
	return nil
}

// deleteRows deletes the account's keys, memberships, service row and
// principal in one transaction.
func (s *Service) deleteRows(ctx context.Context, id uuid.UUID) error {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("serviceaccount: starting transaction: %w", err)
	}
	steps := []func() error{
		func() error {
			_, err := tx.Credential.Delete().Where(entcredential.PrincipalID(id)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.PrincipalMembership.Delete().Where(principalmembership.PrincipalID(id)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.ServicePrincipal.Delete().Where(serviceprincipal.PrincipalID(id)).Exec(ctx)
			return err
		},
		func() error { return tx.Principal.DeleteOneID(id).Exec(ctx) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return errors.Join(fmt.Errorf("serviceaccount: deleting account: %w", err), tx.Rollback())
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serviceaccount: committing deletion: %w", err)
	}
	return nil
}

func toAccount(p *ent.Principal) *Account {
	a := &Account{
		ID:            p.ID,
		Identifier:    p.Identifier,
		Name:          p.DisplayName,
		Active:        p.Active,
		AllowedScopes: p.AllowedScopes,
		CreatedAt:     p.CreatedAt,
	}
	if p.OrganizationID != nil {
		a.OrganizationID = *p.OrganizationID
	}
	if sp := p.Edges.ServicePrincipal; sp != nil {
		a.Description = sp.Description
		a.CreatedBy = sp.CreatedBy
		a.LastUsedAt = sp.LastUsedAt
	}
	return a
}
