package principal

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/application"
	"github.com/plexusone/systemforge/identity/ent/principal"
)

// DefaultService implements the Service interface.
type DefaultService struct {
	client   *ent.Client
	syncer   authz.RelationshipSyncer
	syncMode authz.SyncMode
	logger   *slog.Logger
}

// ServiceOption configures a DefaultService.
type ServiceOption func(*DefaultService)

// WithAuthzSyncer sets the authorization syncer for keeping authz in sync with identity changes.
func WithAuthzSyncer(syncer authz.RelationshipSyncer) ServiceOption {
	return func(s *DefaultService) {
		s.syncer = syncer
	}
}

// WithSyncMode sets the sync mode (strict or eventual).
func WithSyncMode(mode authz.SyncMode) ServiceOption {
	return func(s *DefaultService) {
		s.syncMode = mode
	}
}

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *DefaultService) {
		s.logger = logger
	}
}

// NewService creates a new PrincipalService.
func NewService(client *ent.Client, opts ...ServiceOption) Service {
	s := &DefaultService{
		client:   client,
		syncer:   noop.NewSyncer(),
		syncMode: authz.SyncModeEventual,
		logger:   slog.Default(),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GetByID retrieves a principal by ID.
func (s *DefaultService) GetByID(ctx context.Context, id uuid.UUID) (*Principal, error) {
	p, err := s.client.Principal.
		Query().
		Where(principal.ID(id)).
		WithHuman().
		WithApplication().
		WithAgent().
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("principal not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}
	return entPrincipalToModel(p), nil
}

// GetByIdentifier retrieves a principal by unique identifier.
func (s *DefaultService) GetByIdentifier(ctx context.Context, identifier string) (*Principal, error) {
	p, err := s.client.Principal.
		Query().
		Where(principal.IdentifierEQ(identifier)).
		WithHuman().
		WithApplication().
		WithAgent().
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("principal not found: %s", identifier)
		}
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}
	return entPrincipalToModel(p), nil
}

// CreateHuman creates a new human principal.
func (s *DefaultService) CreateHuman(ctx context.Context, input CreateHumanInput) (*Principal, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Set default capabilities for human
	caps := DefaultCapabilitiesForType(TypeHuman)
	capsMap := capabilitiesToMap(caps)

	// Create principal
	principalCreate := tx.Principal.Create().
		SetType(principal.TypeHuman).
		SetIdentifier(input.Email).
		SetDisplayName(input.DisplayName).
		SetActive(true).
		SetCapabilities(capsMap).
		SetAllowedScopes(input.AllowedScopes)

	if input.OrganizationID != nil {
		principalCreate.SetOrganizationID(*input.OrganizationID)
	}
	if input.Metadata != nil {
		principalCreate.SetMetadata(input.Metadata)
	}

	p, err := principalCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal: %w", err)
	}

	// Create human extension
	humanCreate := tx.Human.Create().
		SetPrincipalID(p.ID).
		SetEmail(input.Email).
		SetIsPlatformAdmin(input.IsPlatformAdmin)

	if input.GivenName != "" {
		humanCreate.SetGivenName(input.GivenName)
	}
	if input.FamilyName != "" {
		humanCreate.SetFamilyName(input.FamilyName)
	}
	if input.AvatarURL != nil {
		humanCreate.SetAvatarURL(*input.AvatarURL)
	}
	if input.Locale != "" {
		humanCreate.SetLocale(input.Locale)
	}
	if input.Timezone != "" {
		humanCreate.SetTimezone(input.Timezone)
	}

	h, err := humanCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create human extension: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.RegisterPrincipal(ctx, p.ID); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync principal to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync principal to authz", "principal_id", p.ID, "error", syncErr)
	}

	// Set platform admin if applicable
	if input.IsPlatformAdmin {
		if syncErr := s.syncer.SetPlatformAdmin(ctx, p.ID, true); syncErr != nil {
			if s.syncMode == authz.SyncModeStrict {
				return nil, fmt.Errorf("failed to sync platform admin to authz: %w", syncErr)
			}
			s.logger.Warn("failed to sync platform admin to authz", "principal_id", p.ID, "error", syncErr)
		}
	}

	// Build result
	result := &Principal{
		ID:            p.ID,
		Type:          TypeHuman,
		Identifier:    p.Identifier,
		DisplayName:   p.DisplayName,
		Active:        p.Active,
		Capabilities:  caps,
		AllowedScopes: p.AllowedScopes,
		Metadata:      p.Metadata,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
		Human: &Human{
			Email:           h.Email,
			GivenName:       h.GivenName,
			FamilyName:      h.FamilyName,
			AvatarURL:       h.AvatarURL,
			Locale:          h.Locale,
			Timezone:        h.Timezone,
			IsPlatformAdmin: h.IsPlatformAdmin,
			LastLoginAt:     h.LastLoginAt,
			EmailVerifiedAt: h.EmailVerifiedAt,
		},
	}
	if p.OrganizationID != nil {
		result.OrganizationID = p.OrganizationID
	}

	return result, nil
}

// CreateApplication creates a new application principal.
func (s *DefaultService) CreateApplication(ctx context.Context, input CreateApplicationInput) (*Principal, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Set default capabilities for application
	caps := DefaultCapabilitiesForType(TypeApplication)
	capsMap := capabilitiesToMap(caps)

	// Create principal
	principalCreate := tx.Principal.Create().
		SetType(principal.TypeApplication).
		SetIdentifier(input.ClientID).
		SetDisplayName(input.DisplayName).
		SetActive(true).
		SetCapabilities(capsMap).
		SetAllowedScopes(input.AllowedScopes)

	if input.OrganizationID != nil {
		principalCreate.SetOrganizationID(*input.OrganizationID)
	}
	if input.Metadata != nil {
		principalCreate.SetMetadata(input.Metadata)
	}

	p, err := principalCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal: %w", err)
	}

	// Set defaults
	accessTTL := 900
	if input.AccessTokenTTLSeconds > 0 {
		accessTTL = input.AccessTokenTTLSeconds
	}
	refreshTTL := 604800
	if input.RefreshTokenTTLSeconds > 0 {
		refreshTTL = input.RefreshTokenTTLSeconds
	}

	// Create application extension
	appCreate := tx.Application.Create().
		SetPrincipalID(p.ID).
		SetClientID(input.ClientID).
		SetAppType(mapAppType(input.AppType)).
		SetRedirectUris(input.RedirectURIs).
		SetAllowedGrants(input.AllowedGrants).
		SetAllowedResponseTypes(input.AllowedResponseTypes).
		SetAccessTokenTTL(accessTTL).
		SetRefreshTokenTTL(refreshTTL).
		SetRefreshTokenRotation(input.RefreshTokenRotation).
		SetFirstParty(input.FirstParty).
		SetPublic(input.Public)

	if input.Description != nil {
		appCreate.SetDescription(*input.Description)
	}
	if input.LogoURL != nil {
		appCreate.SetLogoURL(*input.LogoURL)
	}

	app, err := appCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create application extension: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.RegisterPrincipal(ctx, p.ID); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync principal to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync principal to authz", "principal_id", p.ID, "error", syncErr)
	}

	// Build result
	result := &Principal{
		ID:            p.ID,
		Type:          TypeApplication,
		Identifier:    p.Identifier,
		DisplayName:   p.DisplayName,
		Active:        p.Active,
		Capabilities:  caps,
		AllowedScopes: p.AllowedScopes,
		Metadata:      p.Metadata,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
		Application: &Application{
			ClientID:               app.ClientID,
			AppType:                input.AppType,
			RedirectURIs:           app.RedirectUris,
			AllowedGrants:          app.AllowedGrants,
			AllowedResponseTypes:   app.AllowedResponseTypes,
			AccessTokenTTLSeconds:  app.AccessTokenTTL,
			RefreshTokenTTLSeconds: app.RefreshTokenTTL,
			RefreshTokenRotation:   app.RefreshTokenRotation,
			FirstParty:             app.FirstParty,
			Public:                 app.Public,
			LogoURL:                strPtr(app.LogoURL),
			Description:            strPtr(app.Description),
		},
	}
	if p.OrganizationID != nil {
		result.OrganizationID = p.OrganizationID
	}

	return result, nil
}

// CreateAgent creates a new agent principal.
func (s *DefaultService) CreateAgent(ctx context.Context, input CreateAgentInput) (*Principal, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Set default capabilities for agent
	caps := DefaultCapabilitiesForType(TypeAgent)
	if !input.RequiresConfirmation {
		caps.RequiresApproval = false
	}
	capsMap := capabilitiesToMap(caps)

	// Create principal
	principalCreate := tx.Principal.Create().
		SetType(principal.TypeAgent).
		SetIdentifier(input.Identifier).
		SetDisplayName(input.DisplayName).
		SetActive(true).
		SetCapabilities(capsMap).
		SetAllowedScopes(input.AllowedScopes)

	if input.OrganizationID != nil {
		principalCreate.SetOrganizationID(*input.OrganizationID)
	}
	if input.Metadata != nil {
		principalCreate.SetMetadata(input.Metadata)
	}

	p, err := principalCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal: %w", err)
	}

	// Set defaults
	maxLifetime := 3600
	if input.MaxTokenLifetimeSeconds > 0 {
		maxLifetime = input.MaxTokenLifetimeSeconds
	}

	// Create agent extension
	agentCreate := tx.Agent.Create().
		SetPrincipalID(p.ID).
		SetModelID(input.ModelID).
		SetCapabilityConstraints(input.CapabilityConstraints).
		SetResourceConstraints(input.ResourceConstraints).
		SetMaxTokenLifetime(maxLifetime).
		SetRequiresConfirmation(input.RequiresConfirmation)

	if input.Version != "" {
		agentCreate.SetVersion(input.Version)
	}
	if input.DelegatingPrincipalID != nil {
		agentCreate.SetDelegatingPrincipalID(*input.DelegatingPrincipalID)
	}

	agent, err := agentCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent extension: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.RegisterPrincipal(ctx, p.ID); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync principal to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync principal to authz", "principal_id", p.ID, "error", syncErr)
	}

	// Build result
	result := &Principal{
		ID:            p.ID,
		Type:          TypeAgent,
		Identifier:    p.Identifier,
		DisplayName:   p.DisplayName,
		Active:        p.Active,
		Capabilities:  caps,
		AllowedScopes: p.AllowedScopes,
		Metadata:      p.Metadata,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
		Agent: &Agent{
			ModelID:                 agent.ModelID,
			Version:                 agent.Version,
			DelegatingPrincipalID:   agent.DelegatingPrincipalID,
			CapabilityConstraints:   agent.CapabilityConstraints,
			ResourceConstraints:     agent.ResourceConstraints,
			MaxTokenLifetimeSeconds: agent.MaxTokenLifetime,
			SessionID:               agent.SessionID,
			RequiresConfirmation:    agent.RequiresConfirmation,
		},
	}
	if p.OrganizationID != nil {
		result.OrganizationID = p.OrganizationID
	}

	return result, nil
}

// CreateService creates a new service principal.
func (s *DefaultService) CreateService(ctx context.Context, input CreateServiceInput) (*Principal, error) {
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Set default capabilities for service
	caps := DefaultCapabilitiesForType(TypeService)
	capsMap := capabilitiesToMap(caps)

	// Create principal
	principalCreate := tx.Principal.Create().
		SetType(principal.TypeService).
		SetIdentifier(input.Identifier).
		SetDisplayName(input.DisplayName).
		SetActive(true).
		SetCapabilities(capsMap).
		SetAllowedScopes(input.AllowedScopes)

	if input.OrganizationID != nil {
		principalCreate.SetOrganizationID(*input.OrganizationID)
	}
	if input.Metadata != nil {
		principalCreate.SetMetadata(input.Metadata)
	}

	p, err := principalCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create principal: %w", err)
	}

	// Create service extension
	svcCreate := tx.ServicePrincipal.Create().
		SetPrincipalID(p.ID).
		SetServiceType(input.ServiceType).
		SetAllowedIps(input.AllowedIPs)

	if input.Description != nil {
		svcCreate.SetDescription(*input.Description)
	}
	if input.CreatedBy != nil {
		svcCreate.SetCreatedBy(*input.CreatedBy)
	}

	svc, err := svcCreate.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create service extension: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Sync to authorization backend
	if syncErr := s.syncer.RegisterPrincipal(ctx, p.ID); syncErr != nil {
		if s.syncMode == authz.SyncModeStrict {
			return nil, fmt.Errorf("failed to sync principal to authz: %w", syncErr)
		}
		s.logger.Warn("failed to sync principal to authz", "principal_id", p.ID, "error", syncErr)
	}

	// Build result
	result := &Principal{
		ID:            p.ID,
		Type:          TypeService,
		Identifier:    p.Identifier,
		DisplayName:   p.DisplayName,
		Active:        p.Active,
		Capabilities:  caps,
		AllowedScopes: p.AllowedScopes,
		Metadata:      p.Metadata,
		CreatedAt:     p.CreatedAt,
		UpdatedAt:     p.UpdatedAt,
		Service: &ServiceData{
			ServiceType: svc.ServiceType,
			Description: strPtr(svc.Description),
			CreatedBy:   svc.CreatedBy,
			LastUsedAt:  svc.LastUsedAt,
			AllowedIPs:  svc.AllowedIps,
		},
	}
	if p.OrganizationID != nil {
		result.OrganizationID = p.OrganizationID
	}

	return result, nil
}

// Update updates an existing principal.
func (s *DefaultService) Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*Principal, error) {
	update := s.client.Principal.UpdateOneID(id)

	if input.DisplayName != nil {
		update.SetDisplayName(*input.DisplayName)
	}
	if input.Active != nil {
		update.SetActive(*input.Active)
	}
	if input.AllowedScopes != nil {
		update.SetAllowedScopes(input.AllowedScopes)
	}
	if input.Capabilities != nil {
		update.SetCapabilities(capabilitiesToMap(*input.Capabilities))
	}
	if input.Metadata != nil {
		update.SetMetadata(input.Metadata)
	}

	p, err := update.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to update principal: %w", err)
	}

	return s.GetByID(ctx, p.ID)
}

// UpdateHuman updates a human principal.
func (s *DefaultService) UpdateHuman(ctx context.Context, id uuid.UUID, input UpdateHumanInput) (*Principal, error) {
	// First update the base principal
	if _, err := s.Update(ctx, id, input.UpdateInput); err != nil {
		return nil, err
	}

	// Then update the human extension
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithHuman().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.Human == nil {
		return nil, fmt.Errorf("principal is not a human: %s", id)
	}

	update := s.client.Human.UpdateOne(p.Edges.Human)

	if input.GivenName != nil {
		update.SetGivenName(*input.GivenName)
	}
	if input.FamilyName != nil {
		update.SetFamilyName(*input.FamilyName)
	}
	if input.AvatarURL != nil {
		update.SetAvatarURL(*input.AvatarURL)
	}
	if input.Locale != nil {
		update.SetLocale(*input.Locale)
	}
	if input.Timezone != nil {
		update.SetTimezone(*input.Timezone)
	}
	if input.IsPlatformAdmin != nil {
		update.SetIsPlatformAdmin(*input.IsPlatformAdmin)
	}

	if _, err = update.Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update human extension: %w", err)
	}

	return s.GetByID(ctx, id)
}

// UpdateApplication updates an application principal.
func (s *DefaultService) UpdateApplication(ctx context.Context, id uuid.UUID, input UpdateApplicationInput) (*Principal, error) {
	// First update the base principal
	if _, err := s.Update(ctx, id, input.UpdateInput); err != nil {
		return nil, err
	}

	// Then update the application extension
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithApplication().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.Application == nil {
		return nil, fmt.Errorf("principal is not an application: %s", id)
	}

	update := s.client.Application.UpdateOne(p.Edges.Application)

	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.LogoURL != nil {
		update.SetLogoURL(*input.LogoURL)
	}
	if input.RedirectURIs != nil {
		update.SetRedirectUris(input.RedirectURIs)
	}
	if input.AllowedGrants != nil {
		update.SetAllowedGrants(input.AllowedGrants)
	}
	if input.AllowedResponseTypes != nil {
		update.SetAllowedResponseTypes(input.AllowedResponseTypes)
	}
	if input.AccessTokenTTLSeconds != nil {
		update.SetAccessTokenTTL(*input.AccessTokenTTLSeconds)
	}
	if input.RefreshTokenTTLSeconds != nil {
		update.SetRefreshTokenTTL(*input.RefreshTokenTTLSeconds)
	}
	if input.RefreshTokenRotation != nil {
		update.SetRefreshTokenRotation(*input.RefreshTokenRotation)
	}
	if input.FirstParty != nil {
		update.SetFirstParty(*input.FirstParty)
	}

	if _, err = update.Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update application extension: %w", err)
	}

	return s.GetByID(ctx, id)
}

// UpdateAgent updates an agent principal.
func (s *DefaultService) UpdateAgent(ctx context.Context, id uuid.UUID, input UpdateAgentInput) (*Principal, error) {
	// First update the base principal
	if _, err := s.Update(ctx, id, input.UpdateInput); err != nil {
		return nil, err
	}

	// Then update the agent extension
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithAgent().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.Agent == nil {
		return nil, fmt.Errorf("principal is not an agent: %s", id)
	}

	update := s.client.Agent.UpdateOne(p.Edges.Agent)

	if input.Version != nil {
		update.SetVersion(*input.Version)
	}
	if input.CapabilityConstraints != nil {
		update.SetCapabilityConstraints(input.CapabilityConstraints)
	}
	if input.ResourceConstraints != nil {
		update.SetResourceConstraints(input.ResourceConstraints)
	}
	if input.MaxTokenLifetimeSeconds != nil {
		update.SetMaxTokenLifetime(*input.MaxTokenLifetimeSeconds)
	}
	if input.RequiresConfirmation != nil {
		update.SetRequiresConfirmation(*input.RequiresConfirmation)
	}

	if _, err = update.Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update agent extension: %w", err)
	}

	return s.GetByID(ctx, id)
}

// UpdateService updates a service principal.
func (s *DefaultService) UpdateService(ctx context.Context, id uuid.UUID, input UpdateServiceInput) (*Principal, error) {
	// First update the base principal
	if _, err := s.Update(ctx, id, input.UpdateInput); err != nil {
		return nil, err
	}

	// Then update the service extension
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithServicePrincipal().
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.ServicePrincipal == nil {
		return nil, fmt.Errorf("principal is not a service: %s", id)
	}

	update := s.client.ServicePrincipal.UpdateOne(p.Edges.ServicePrincipal)

	if input.Description != nil {
		update.SetDescription(*input.Description)
	}
	if input.AllowedIPs != nil {
		update.SetAllowedIps(input.AllowedIPs)
	}

	if _, err = update.Save(ctx); err != nil {
		return nil, fmt.Errorf("failed to update service extension: %w", err)
	}

	return s.GetByID(ctx, id)
}

// Deactivate deactivates a principal.
func (s *DefaultService) Deactivate(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Principal.UpdateOneID(id).
		SetActive(false).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to deactivate principal: %w", err)
	}
	return nil
}

// Reactivate reactivates a principal.
func (s *DefaultService) Reactivate(ctx context.Context, id uuid.UUID) error {
	_, err := s.client.Principal.UpdateOneID(id).
		SetActive(true).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to reactivate principal: %w", err)
	}
	return nil
}

// Helper functions

func entPrincipalToModel(p *ent.Principal) *Principal {
	result := &Principal{
		ID:             p.ID,
		Type:           Type(p.Type.String()),
		Identifier:     p.Identifier,
		DisplayName:    p.DisplayName,
		OrganizationID: p.OrganizationID,
		Active:         p.Active,
		Capabilities:   mapToCapabilities(p.Capabilities),
		AllowedScopes:  p.AllowedScopes,
		Metadata:       p.Metadata,
		CreatedAt:      p.CreatedAt,
		UpdatedAt:      p.UpdatedAt,
	}

	// Populate type-specific extension
	if p.Edges.Human != nil {
		h := p.Edges.Human
		result.Human = &Human{
			Email:           h.Email,
			GivenName:       h.GivenName,
			FamilyName:      h.FamilyName,
			AvatarURL:       h.AvatarURL,
			Locale:          h.Locale,
			Timezone:        h.Timezone,
			IsPlatformAdmin: h.IsPlatformAdmin,
			LastLoginAt:     h.LastLoginAt,
			EmailVerifiedAt: h.EmailVerifiedAt,
		}
	}

	if p.Edges.Application != nil {
		app := p.Edges.Application
		result.Application = &Application{
			ClientID:               app.ClientID,
			AppType:                AppType(app.AppType.String()),
			RedirectURIs:           app.RedirectUris,
			AllowedGrants:          app.AllowedGrants,
			AllowedResponseTypes:   app.AllowedResponseTypes,
			AccessTokenTTLSeconds:  app.AccessTokenTTL,
			RefreshTokenTTLSeconds: app.RefreshTokenTTL,
			RefreshTokenRotation:   app.RefreshTokenRotation,
			FirstParty:             app.FirstParty,
			Public:                 app.Public,
			LogoURL:                strPtr(app.LogoURL),
			Description:            strPtr(app.Description),
		}
	}

	if p.Edges.Agent != nil {
		agent := p.Edges.Agent
		result.Agent = &Agent{
			ModelID:                 agent.ModelID,
			Version:                 agent.Version,
			DelegatingPrincipalID:   agent.DelegatingPrincipalID,
			CapabilityConstraints:   agent.CapabilityConstraints,
			ResourceConstraints:     agent.ResourceConstraints,
			MaxTokenLifetimeSeconds: agent.MaxTokenLifetime,
			SessionID:               agent.SessionID,
			RequiresConfirmation:    agent.RequiresConfirmation,
		}
	}

	if p.Edges.ServicePrincipal != nil {
		svc := p.Edges.ServicePrincipal
		result.Service = &ServiceData{
			ServiceType: svc.ServiceType,
			Description: strPtr(svc.Description),
			CreatedBy:   svc.CreatedBy,
			LastUsedAt:  svc.LastUsedAt,
			AllowedIPs:  svc.AllowedIps,
		}
	}

	return result
}

func capabilitiesToMap(c Capabilities) map[string]bool {
	return map[string]bool{
		"can_access_ui":       c.CanAccessUI,
		"can_manage_profile":  c.CanManageProfile,
		"can_act_on_behalf":   c.CanActOnBehalf,
		"can_delegate":        c.CanDelegate,
		"requires_approval":   c.RequiresApproval,
		"can_bypass_rls":      c.CanBypassRLS,
		"can_request_offline": c.CanRequestOffline,
	}
}

func mapToCapabilities(m map[string]bool) Capabilities {
	return Capabilities{
		CanAccessUI:       m["can_access_ui"],
		CanManageProfile:  m["can_manage_profile"],
		CanActOnBehalf:    m["can_act_on_behalf"],
		CanDelegate:       m["can_delegate"],
		RequiresApproval:  m["requires_approval"],
		CanBypassRLS:      m["can_bypass_rls"],
		CanRequestOffline: m["can_request_offline"],
	}
}

func mapAppType(t AppType) application.AppType {
	switch t {
	case AppTypeWeb:
		return application.AppTypeWeb
	case AppTypeSPA:
		return application.AppTypeSpa
	case AppTypeNative:
		return application.AppTypeNative
	case AppTypeMachine:
		return application.AppTypeMachine
	default:
		return application.AppTypeWeb
	}
}

// strPtr returns a pointer to a string, or nil if the string is empty.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// UpdateLastLogin updates the last login timestamp for a human principal.
func (s *DefaultService) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithHuman().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.Human == nil {
		return fmt.Errorf("principal is not a human: %s", id)
	}

	now := time.Now()
	_, err = s.client.Human.UpdateOne(p.Edges.Human).
		SetLastLoginAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// MarkEmailVerified marks a human principal's email as verified.
func (s *DefaultService) MarkEmailVerified(ctx context.Context, id uuid.UUID) error {
	p, err := s.client.Principal.Query().
		Where(principal.ID(id)).
		WithHuman().
		Only(ctx)
	if err != nil {
		return fmt.Errorf("failed to get principal: %w", err)
	}

	if p.Edges.Human == nil {
		return fmt.Errorf("principal is not a human: %s", id)
	}

	now := time.Now()
	_, err = s.client.Human.UpdateOne(p.Edges.Human).
		SetEmailVerifiedAt(now).
		Save(ctx)
	if err != nil {
		return fmt.Errorf("failed to mark email verified: %w", err)
	}

	return nil
}
