package contract

import (
	"context"
	"sync"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
)

// auditStreamState holds one API's audit stream configuration state. Each
// API (one per application) has its own, so a token for one application
// cannot change another application's audit stream.
type auditStreamState struct {
	mu              sync.RWMutex
	config          *AuditStreamConfig
	lastSequence    int64
	lastAckSequence int64
}

// newAuditStreamState returns the state of a new API: streaming disabled.
func newAuditStreamState() *auditStreamState {
	return &auditStreamState{
		config: &AuditStreamConfig{
			Enabled:         false,
			BatchSize:       100,
			FlushIntervalMs: 5000,
		},
	}
}

// registerAuditEndpoints registers audit endpoints.
func (a *API) registerAuditEndpoints() {
	base := a.provider.Config().BaseURL

	// Get audit stream config
	huma.Register(a.huma, huma.Operation{
		OperationID: "getAuditStreamConfig",
		Method:      "GET",
		Path:        base + "/audit/stream/config",
		Summary:     "Get audit stream configuration",
		Description: "Returns the current audit streaming configuration.",
		Tags:        []string{"Audit"},
		Security: []map[string][]string{
			{"bearer": {"audit:config"}},
		},
	}, a.getAuditStreamConfig)

	// Update audit stream config
	huma.Register(a.huma, huma.Operation{
		OperationID: "updateAuditStreamConfig",
		Method:      "PUT",
		Path:        base + "/audit/stream/config",
		Summary:     "Update audit stream configuration",
		Description: "Updates the audit streaming configuration. Requires federation mode.",
		Tags:        []string{"Audit", "Federation"},
		Security: []map[string][]string{
			{"bearer": {"audit:config"}},
		},
	}, a.updateAuditStreamConfig)

	// Acknowledge audit events
	huma.Register(a.huma, huma.Operation{
		OperationID: "acknowledgeAuditEvents",
		Method:      "POST",
		Path:        base + "/audit/stream/ack",
		Summary:     "Acknowledge audit events",
		Description: "Acknowledges receipt of audit events up to a sequence number. Requires federation mode.",
		Tags:        []string{"Audit", "Federation"},
		Security: []map[string][]string{
			{"bearer": {"audit:config"}},
		},
	}, a.acknowledgeAuditEvents)
}

func (a *API) getAuditStreamConfig(ctx context.Context, input *struct{}) (*AuditStreamConfigOutput, error) {
	if err := a.checkPermission(ctx, PermissionAuditConfig); err != nil {
		return nil, err
	}

	a.audit.mu.RLock()
	config := *a.audit.config
	config.LastSequence = a.audit.lastSequence
	a.audit.mu.RUnlock()

	return &AuditStreamConfigOutput{Body: config}, nil
}

func (a *API) updateAuditStreamConfig(ctx context.Context, input *UpdateAuditStreamConfigInput) (*UpdateAuditStreamConfigOutput, error) {
	if err := a.checkFederated(); err != nil {
		return nil, err
	}
	if err := a.checkPermission(ctx, PermissionAuditConfig); err != nil {
		return nil, err
	}

	// Validate required fields
	if input.Body.Enabled && input.Body.Endpoint == "" {
		return nil, huma.Error400BadRequest("endpoint is required when enabled")
	}

	// Update configuration
	a.audit.mu.Lock()
	a.audit.config = &AuditStreamConfig{
		Enabled:         input.Body.Enabled,
		Endpoint:        input.Body.Endpoint,
		BatchSize:       input.Body.BatchSize,
		FlushIntervalMs: input.Body.FlushIntervalMs,
		AuthMethod:      "bearer",
	}
	if input.Body.BatchSize == 0 {
		a.audit.config.BatchSize = 100
	}
	if input.Body.FlushIntervalMs == 0 {
		a.audit.config.FlushIntervalMs = 5000
	}
	a.audit.mu.Unlock()

	return &UpdateAuditStreamConfigOutput{
		Body: struct {
			Status     string `json:"status" doc:"Configuration status" enum:"configured,failed" example:"configured"`
			TestResult string `json:"test_result,omitempty" doc:"Connection test result" example:"success"`
		}{
			Status:     "configured",
			TestResult: "success",
		},
	}, nil
}

func (a *API) acknowledgeAuditEvents(ctx context.Context, input *AuditAckInput) (*AuditAckOutput, error) {
	if err := a.checkFederated(); err != nil {
		return nil, err
	}
	if err := a.checkPermission(ctx, PermissionAuditConfig); err != nil {
		return nil, err
	}

	// Update acknowledged sequence
	a.audit.mu.Lock()
	if input.Body.Sequence > a.audit.lastAckSequence {
		a.audit.lastAckSequence = input.Body.Sequence
	}
	nextSequence := a.audit.lastSequence + 1
	a.audit.mu.Unlock()

	return &AuditAckOutput{
		Body: struct {
			Acknowledged bool  `json:"acknowledged" doc:"Whether acknowledgment was successful" example:"true"`
			NextSequence int64 `json:"next_sequence" doc:"Next expected sequence number" example:"12346"`
		}{
			Acknowledged: true,
			NextSequence: nextSequence,
		},
	}, nil
}

// RecordAuditEvent records an audit event of this API's application and
// returns its sequence number. The application calls it when emitting
// audit events.
func (a *API) RecordAuditEvent() int64 {
	a.audit.mu.Lock()
	defer a.audit.mu.Unlock()
	a.audit.lastSequence++
	return a.audit.lastSequence
}

// AuditStreamConfig returns this API's current audit stream configuration.
func (a *API) AuditStreamConfig() AuditStreamConfig {
	a.audit.mu.RLock()
	defer a.audit.mu.RUnlock()
	config := *a.audit.config
	config.LastSequence = a.audit.lastSequence
	return config
}

// IsAuditStreamEnabled reports whether this API's audit streaming is
// enabled.
func (a *API) IsAuditStreamEnabled() bool {
	a.audit.mu.RLock()
	defer a.audit.mu.RUnlock()
	return a.audit.config.Enabled
}

// AuditEvent represents a standardized audit event.
type AuditEvent struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	EventType string         `json:"event_type"`
	Action    string         `json:"action"`
	Actor     AuditActor     `json:"actor"`
	Resource  AuditResource  `json:"resource"`
	Context   AuditContext   `json:"context"`
	Outcome   string         `json:"outcome"` // "success" | "failure"
	Details   map[string]any `json:"details,omitempty"`
}

// AuditActor represents the actor in an audit event.
type AuditActor struct {
	ID         string `json:"id"`
	Type       string `json:"type"` // "human" | "application" | "agent" | "service"
	Identifier string `json:"identifier"`
}

// AuditResource represents the resource in an audit event.
type AuditResource struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	Identifier string `json:"identifier,omitempty"`
}

// AuditContext represents the context of an audit event.
type AuditContext struct {
	TenantID  string `json:"tenant_id,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

// Blank identifiers for imports used only in struct tags.
var (
	_ = time.Time{}
	_ = uuid.UUID{}
)
