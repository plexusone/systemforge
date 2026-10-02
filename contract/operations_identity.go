package contract

import (
	"context"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/plexusone/systemforge/identity/ent"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
)

// registerIdentityEndpoints registers identity endpoints.
func (a *API) registerIdentityEndpoints() {
	base := a.provider.Config().BaseURL

	// List principals
	huma.Register(a.huma, huma.Operation{
		OperationID: "listPrincipals",
		Method:      "GET",
		Path:        base + "/identity/principals",
		Summary:     "List principals",
		Description: "Returns a paginated list of principals, optionally filtered by type or tenant.",
		Tags:        []string{"Identity"},
		Security: []map[string][]string{
			{"bearer": {"identity:read"}},
		},
	}, a.listPrincipals)

	// Get principal by ID
	huma.Register(a.huma, huma.Operation{
		OperationID: "getPrincipal",
		Method:      "GET",
		Path:        base + "/identity/principals/{id}",
		Summary:     "Get principal by ID",
		Description: "Returns a single principal by its unique identifier.",
		Tags:        []string{"Identity"},
		Security: []map[string][]string{
			{"bearer": {"identity:read"}},
		},
	}, a.getPrincipal)

	// Lookup principal
	huma.Register(a.huma, huma.Operation{
		OperationID: "lookupPrincipal",
		Method:      "POST",
		Path:        base + "/identity/principals/lookup",
		Summary:     "Lookup principal by identifier",
		Description: "Finds a principal by its identifier (email, client_id, etc.).",
		Tags:        []string{"Identity"},
		Security: []map[string][]string{
			{"bearer": {"identity:read"}},
		},
	}, a.lookupPrincipal)

	// Sync identities (federation only)
	huma.Register(a.huma, huma.Operation{
		OperationID: "syncIdentities",
		Method:      "POST",
		Path:        base + "/identity/sync",
		Summary:     "Sync identities from SystemAuth",
		Description: "Synchronizes principal data from SystemAuth. Requires federation mode.",
		Tags:        []string{"Identity", "Federation"},
		Security: []map[string][]string{
			{"bearer": {"identity:sync"}},
		},
	}, a.syncIdentities)

	// List tenants
	huma.Register(a.huma, huma.Operation{
		OperationID: "listTenants",
		Method:      "GET",
		Path:        base + "/identity/tenants",
		Summary:     "List tenants",
		Description: "Returns a list of all tenants (organizations).",
		Tags:        []string{"Identity"},
		Security: []map[string][]string{
			{"bearer": {"identity:read"}},
		},
	}, a.listTenants)
}

func (a *API) listPrincipals(ctx context.Context, input *PrincipalsListInput) (*PrincipalsListOutput, error) {
	if err := a.checkPermission(ctx, PermissionIdentityRead); err != nil {
		return nil, err
	}

	limit := input.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	entClient := a.provider.EntClient()
	q := entClient.Principal.Query().
		WithHuman().
		WithApplication().
		WithAgent().
		WithServicePrincipal().
		Limit(limit)

	if input.Type != "" {
		q = q.Where(entprincipal.TypeEQ(entprincipal.Type(input.Type)))
	}

	if input.TenantID != "" {
		tenantID, err := uuid.Parse(input.TenantID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid tenant_id format")
		}
		q = q.Where(entprincipal.OrganizationIDEQ(tenantID))
	}

	principals, err := q.All(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to query principals", err)
	}

	result := make([]ContractPrincipal, len(principals))
	for i, p := range principals {
		result[i] = entPrincipalToContract(p)
	}

	return &PrincipalsListOutput{
		Body: struct {
			Principals []ContractPrincipal `json:"principals" doc:"List of principals"`
			NextCursor string              `json:"next_cursor,omitempty" doc:"Cursor for next page"`
			Total      int                 `json:"total" doc:"Total number of principals" example:"42"`
		}{
			Principals: result,
			Total:      len(result),
		},
	}, nil
}

func (a *API) getPrincipal(ctx context.Context, input *PrincipalGetInput) (*PrincipalGetOutput, error) {
	if err := a.checkPermission(ctx, PermissionIdentityRead); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(input.ID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid principal ID format")
	}

	// Use identity service if available
	if svc := a.provider.IdentityService(); svc != nil {
		p, err := svc.GetByID(ctx, id)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return nil, huma.Error404NotFound("principal not found")
			}
			return nil, huma.Error500InternalServerError("failed to get principal", err)
		}
		return &PrincipalGetOutput{Body: principalToContract(p)}, nil
	}

	// Fall back to ent client
	entClient := a.provider.EntClient()
	p, err := entClient.Principal.Query().
		Where(entprincipal.ID(id)).
		WithHuman().
		WithApplication().
		WithAgent().
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, huma.Error404NotFound("principal not found")
		}
		return nil, huma.Error500InternalServerError("failed to get principal", err)
	}

	return &PrincipalGetOutput{Body: entPrincipalToContract(p)}, nil
}

func (a *API) lookupPrincipal(ctx context.Context, input *LookupInput) (*LookupOutput, error) {
	if err := a.checkPermission(ctx, PermissionIdentityRead); err != nil {
		return nil, err
	}

	if input.Body.Identifier == "" {
		return nil, huma.Error400BadRequest("identifier is required")
	}

	// Use identity service if available
	if svc := a.provider.IdentityService(); svc != nil {
		p, err := svc.GetByIdentifier(ctx, input.Body.Identifier)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				return &LookupOutput{Body: struct {
					Principal *ContractPrincipal `json:"principal" doc:"Found principal, or null if not found"`
				}{Principal: nil}}, nil
			}
			return nil, huma.Error500InternalServerError("failed to lookup principal", err)
		}
		cp := principalToContract(p)
		return &LookupOutput{Body: struct {
			Principal *ContractPrincipal `json:"principal" doc:"Found principal, or null if not found"`
		}{Principal: &cp}}, nil
	}

	// Fall back to ent client
	entClient := a.provider.EntClient()
	p, err := entClient.Principal.Query().
		Where(entprincipal.IdentifierEQ(input.Body.Identifier)).
		WithHuman().
		WithApplication().
		WithAgent().
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return &LookupOutput{Body: struct {
				Principal *ContractPrincipal `json:"principal" doc:"Found principal, or null if not found"`
			}{Principal: nil}}, nil
		}
		return nil, huma.Error500InternalServerError("failed to lookup principal", err)
	}

	cp := entPrincipalToContract(p)
	return &LookupOutput{Body: struct {
		Principal *ContractPrincipal `json:"principal" doc:"Found principal, or null if not found"`
	}{Principal: &cp}}, nil
}

//nolint:dupl // Sync handlers are intentionally similar but handle different types
func (a *API) syncIdentities(ctx context.Context, input *IdentitySyncInput) (*IdentitySyncOutput, error) {
	if err := a.checkFederated(); err != nil {
		return nil, err
	}
	if err := a.checkPermission(ctx, PermissionIdentitySync); err != nil {
		return nil, err
	}
	if err := a.startSync(); err != nil {
		return nil, err
	}
	defer a.provider.FederationState().EndSync()

	// Validate federation ID matches
	expectedFedID := a.provider.FederationState().FederationID()
	if expectedFedID != nil && input.Body.FederationID != *expectedFedID {
		return nil, huma.Error400BadRequest("federation ID mismatch")
	}

	// Process each principal
	synced := make([]uuid.UUID, 0, len(input.Body.Principals))
	failed := make([]SyncFailure, 0)

	for _, sp := range input.Body.Principals {
		// For now, just track as synced (actual implementation would create/update principals)
		synced = append(synced, sp.GlobalID)
	}

	a.provider.FederationState().SetLastIdentitySync(time.Now())

	return &IdentitySyncOutput{
		Body: struct {
			Synced    []uuid.UUID   `json:"synced" doc:"Successfully synced principal IDs"`
			Failed    []SyncFailure `json:"failed" doc:"Failed sync operations"`
			SyncToken string        `json:"sync_token" doc:"Updated sync token"`
		}{
			Synced:    synced,
			Failed:    failed,
			SyncToken: input.Body.SyncToken,
		},
	}, nil
}

func (a *API) listTenants(ctx context.Context, input *struct{}) (*TenantsListOutput, error) {
	if err := a.checkPermission(ctx, PermissionIdentityRead); err != nil {
		return nil, err
	}

	entClient := a.provider.EntClient()
	orgs, err := entClient.Organization.Query().All(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("failed to query tenants", err)
	}

	tenants := make([]Tenant, len(orgs))
	for i, org := range orgs {
		tenants[i] = Tenant{
			ID:        org.ID,
			Name:      org.Name,
			Slug:      org.Slug,
			Active:    org.Active,
			CreatedAt: org.CreatedAt,
		}
	}

	return &TenantsListOutput{
		Body: struct {
			Tenants []Tenant `json:"tenants" doc:"List of tenants"`
		}{
			Tenants: tenants,
		},
	}, nil
}

// entPrincipalToContract converts an ent principal to a contract principal.
func entPrincipalToContract(p *ent.Principal) ContractPrincipal {
	cp := ContractPrincipal{
		ID:             p.ID,
		Type:           p.Type.String(),
		Identifier:     p.Identifier,
		DisplayName:    p.DisplayName,
		Active:         p.Active,
		OrganizationID: p.OrganizationID,
		Capabilities:   p.Capabilities,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}

	if p.Edges.Human != nil {
		h := p.Edges.Human
		cp.Human = &ContractHuman{
			Email:      h.Email,
			GivenName:  h.GivenName,
			FamilyName: h.FamilyName,
		}
	}

	if p.Edges.Application != nil {
		app := p.Edges.Application
		cp.Application = &ContractApp{
			ClientID:    app.ClientID,
			AppType:     app.AppType.String(),
			FirstParty:  app.FirstParty,
			Description: app.Description,
		}
	}

	if p.Edges.Agent != nil {
		agent := p.Edges.Agent
		cp.Agent = &ContractAgent{
			ModelID:              agent.ModelID,
			Version:              agent.Version,
			DelegatingPrincipal:  agent.DelegatingPrincipalID,
			RequiresConfirmation: agent.RequiresConfirmation,
		}
	}

	if p.Edges.ServicePrincipal != nil {
		svc := p.Edges.ServicePrincipal
		cp.Service = &ContractService{
			ServiceType: svc.ServiceType,
			Description: svc.Description,
		}
	}

	return cp
}

// principalToContract converts a principal.Principal to a contract principal.
func principalToContract(p *principal.Principal) ContractPrincipal {
	cp := ContractPrincipal{
		ID:             p.ID,
		Type:           string(p.Type),
		Identifier:     p.Identifier,
		DisplayName:    p.DisplayName,
		Active:         p.Active,
		OrganizationID: p.OrganizationID,
		Capabilities: map[string]bool{
			"can_access_ui":       p.Capabilities.CanAccessUI,
			"can_manage_profile":  p.Capabilities.CanManageProfile,
			"can_act_on_behalf":   p.Capabilities.CanActOnBehalf,
			"can_delegate":        p.Capabilities.CanDelegate,
			"requires_approval":   p.Capabilities.RequiresApproval,
			"can_bypass_rls":      p.Capabilities.CanBypassRLS,
			"can_request_offline": p.Capabilities.CanRequestOffline,
		},
		CreatedAt: p.CreatedAt,
		UpdatedAt: p.UpdatedAt,
	}

	if p.Human != nil {
		cp.Human = &ContractHuman{
			Email:      p.Human.Email,
			GivenName:  p.Human.GivenName,
			FamilyName: p.Human.FamilyName,
		}
	}

	if p.Application != nil {
		desc := ""
		if p.Application.Description != nil {
			desc = *p.Application.Description
		}
		cp.Application = &ContractApp{
			ClientID:    p.Application.ClientID,
			AppType:     string(p.Application.AppType),
			FirstParty:  p.Application.FirstParty,
			Description: desc,
		}
	}

	if p.Agent != nil {
		cp.Agent = &ContractAgent{
			ModelID:              p.Agent.ModelID,
			Version:              p.Agent.Version,
			DelegatingPrincipal:  p.Agent.DelegatingPrincipalID,
			RequiresConfirmation: p.Agent.RequiresConfirmation,
		}
	}

	if p.Service != nil {
		desc := ""
		if p.Service.Description != nil {
			desc = *p.Service.Description
		}
		cp.Service = &ContractService{
			ServiceType: p.Service.ServiceType,
			Description: desc,
		}
	}

	return cp
}
