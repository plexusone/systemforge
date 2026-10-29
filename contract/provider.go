package contract

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/principal"
)

// IdentityService provides identity-related operations for the contract.
type IdentityService interface {
	// GetByID retrieves a principal by ID.
	GetByID(ctx context.Context, id uuid.UUID) (*principal.Principal, error)

	// GetByIdentifier retrieves a principal by unique identifier.
	GetByIdentifier(ctx context.Context, identifier string) (*principal.Principal, error)
}

// PolicyService provides policy-related operations for the contract.
type PolicyService interface {
	authz.DecisionAuthorizer
}

// HealthChecker provides health check functionality.
type HealthChecker interface {
	// Check returns the health status of a component.
	// Returns "healthy", "degraded", or "unhealthy".
	Check(ctx context.Context) string
}

// FederationState manages the federation state for an application.
type FederationState struct {
	mu               sync.RWMutex
	federationID     *uuid.UUID
	lastIdentitySync *time.Time
	lastPolicySync   *time.Time
	syncInProgress   bool
}

// NewFederationState creates a new federation state in standalone mode.
func NewFederationState() *FederationState {
	return &FederationState{}
}

// Status returns the current federation status.
func (s *FederationState) Status() FederationStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.federationID == nil {
		return FederationStatus{
			Status: FederationStatusStandalone,
		}
	}

	return FederationStatus{
		Status:       FederationStatusFederated,
		FederationID: s.federationID,
	}
}

// IsFederated returns true if the application is in federated mode.
func (s *FederationState) IsFederated() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.federationID != nil
}

// FederationID returns the current federation ID, or nil if standalone.
func (s *FederationState) FederationID() *uuid.UUID {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.federationID == nil {
		return nil
	}
	id := *s.federationID
	return &id
}

// SetFederated sets the application to federated mode with the given federation ID.
func (s *FederationState) SetFederated(federationID uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.federationID = &federationID
}

// SetStandalone returns the application to standalone mode.
func (s *FederationState) SetStandalone() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.federationID = nil
	s.lastIdentitySync = nil
	s.lastPolicySync = nil
}

// LastIdentitySync returns the time of the last identity sync.
func (s *FederationState) LastIdentitySync() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastIdentitySync
}

// SetLastIdentitySync updates the last identity sync time.
func (s *FederationState) SetLastIdentitySync(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastIdentitySync = &t
}

// LastPolicySync returns the time of the last policy sync.
func (s *FederationState) LastPolicySync() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastPolicySync
}

// SetLastPolicySync updates the last policy sync time.
func (s *FederationState) SetLastPolicySync(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPolicySync = &t
}

// LastSync returns the most recent sync time (identity or policy).
func (s *FederationState) LastSync() *time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.lastIdentitySync == nil && s.lastPolicySync == nil {
		return nil
	}
	if s.lastIdentitySync == nil {
		return s.lastPolicySync
	}
	if s.lastPolicySync == nil {
		return s.lastIdentitySync
	}
	if s.lastIdentitySync.After(*s.lastPolicySync) {
		return s.lastIdentitySync
	}
	return s.lastPolicySync
}

// IsSyncInProgress returns true if a sync operation is currently running.
func (s *FederationState) IsSyncInProgress() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.syncInProgress
}

// StartSync marks a sync operation as in progress.
// Returns false if a sync is already in progress.
func (s *FederationState) StartSync() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syncInProgress {
		return false
	}
	s.syncInProgress = true
	return true
}

// EndSync marks a sync operation as complete.
func (s *FederationState) EndSync() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncInProgress = false
}

// SyncLagSeconds returns the number of seconds since the last sync.
// Returns 0 if no sync has occurred.
func (s *FederationState) SyncLagSeconds() int {
	lastSync := s.LastSync()
	if lastSync == nil {
		return 0
	}
	return int(time.Since(*lastSync).Seconds())
}

// Provider assembles the services needed for contract endpoints.
type Provider struct {
	config          *Config
	entClient       *ent.Client
	identityService IdentityService
	policyService   PolicyService
	federationState *FederationState
	healthCheckers  map[string]HealthChecker
	vocabularies    *authz.VocabularyRegistry
	startTime       time.Time
	mu              sync.RWMutex
}

// WithVocabularies sets the application role vocabularies that
// GET {base}/policy/vocabularies describes. Without it the endpoint lists
// no application.
func WithVocabularies(registry *authz.VocabularyRegistry) ProviderOption {
	return func(p *Provider) {
		p.vocabularies = registry
	}
}

// Vocabularies returns the application role vocabularies, or nil.
func (p *Provider) Vocabularies() *authz.VocabularyRegistry {
	return p.vocabularies
}

// ProviderOption configures a Provider.
type ProviderOption func(*Provider)

// WithIdentityService sets the identity service.
func WithIdentityService(svc IdentityService) ProviderOption {
	return func(p *Provider) {
		p.identityService = svc
	}
}

// WithPolicyService sets the policy service.
func WithPolicyService(svc PolicyService) ProviderOption {
	return func(p *Provider) {
		p.policyService = svc
	}
}

// WithHealthChecker adds a health checker for a component.
func WithHealthChecker(name string, checker HealthChecker) ProviderOption {
	return func(p *Provider) {
		if p.healthCheckers == nil {
			p.healthCheckers = make(map[string]HealthChecker)
		}
		p.healthCheckers[name] = checker
	}
}

// NewProvider creates a new contract Provider.
func NewProvider(config *Config, entClient *ent.Client, opts ...ProviderOption) (*Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	p := &Provider{
		config:          config,
		entClient:       entClient,
		federationState: NewFederationState(),
		healthCheckers:  make(map[string]HealthChecker),
		startTime:       time.Now(),
	}

	for _, opt := range opts {
		opt(p)
	}

	return p, nil
}

// Config returns the contract configuration.
func (p *Provider) Config() *Config {
	return p.config
}

// EntClient returns the ent client.
func (p *Provider) EntClient() *ent.Client {
	return p.entClient
}

// IdentityService returns the identity service.
func (p *Provider) IdentityService() IdentityService {
	return p.identityService
}

// PolicyService returns the policy service.
func (p *Provider) PolicyService() PolicyService {
	return p.policyService
}

// FederationState returns the federation state.
func (p *Provider) FederationState() *FederationState {
	return p.federationState
}

// HealthCheckers returns the registered health checkers.
func (p *Provider) HealthCheckers() map[string]HealthChecker {
	p.mu.RLock()
	defer p.mu.RUnlock()
	// Return a copy to avoid race conditions
	result := make(map[string]HealthChecker, len(p.healthCheckers))
	for k, v := range p.healthCheckers {
		result[k] = v
	}
	return result
}

// UptimeSeconds returns the number of seconds since the provider started.
func (p *Provider) UptimeSeconds() int64 {
	return int64(time.Since(p.startTime).Seconds())
}

// Metadata returns the metadata response for GET /systemforge/meta.
func (p *Provider) Metadata() *MetadataResponse {
	return &MetadataResponse{
		Body: struct {
			AppID           string            `json:"app_id" doc:"Unique application identifier" example:"my-saas-app"`
			DisplayName     string            `json:"display_name" doc:"Human-readable application name" example:"My SaaS Application"`
			Version         string            `json:"version" doc:"Application version (semver)" example:"1.2.0"`
			ContractVersion string            `json:"contract_version" doc:"Contract specification version" example:"1.0"`
			Capabilities    []string          `json:"capabilities" doc:"Supported contract capabilities" example:"[\"identity\", \"rbac\", \"audit\"]"`
			Endpoints       map[string]string `json:"endpoints" doc:"Endpoint paths by capability"`
			Federation      FederationStatus  `json:"federation" doc:"Current federation status"`
		}{
			AppID:           p.config.AppID,
			DisplayName:     p.config.DisplayName,
			Version:         p.config.Version,
			ContractVersion: p.config.ContractVersion,
			Capabilities:    p.config.CapabilityStrings(),
			Endpoints:       p.config.EndpointPaths(),
			Federation:      p.federationState.Status(),
		},
	}
}
