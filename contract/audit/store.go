// Package audit provides audit event storage and streaming functionality.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Event represents a standardized audit event.
type Event struct {
	ID        uuid.UUID      `json:"id"`
	Sequence  int64          `json:"sequence"`
	Timestamp time.Time      `json:"timestamp"`
	EventType string         `json:"event_type"`
	Action    string         `json:"action"`
	Actor     Actor          `json:"actor"`
	Resource  Resource       `json:"resource"`
	Context   Context        `json:"context"`
	Outcome   string         `json:"outcome"` // "success" | "failure"
	Details   map[string]any `json:"details,omitempty"`
}

// Actor represents the actor in an audit event.
type Actor struct {
	ID         uuid.UUID `json:"id"`
	Type       string    `json:"type"` // "human" | "application" | "agent" | "service"
	Identifier string    `json:"identifier"`
}

// Resource represents the resource in an audit event.
type Resource struct {
	Type       string    `json:"type"`
	ID         uuid.UUID `json:"id"`
	Identifier string    `json:"identifier,omitempty"`
}

// Context represents the context of an audit event.
type Context struct {
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	SessionID string     `json:"session_id,omitempty"`
	ClientIP  string     `json:"client_ip,omitempty"`
	UserAgent string     `json:"user_agent,omitempty"`
	// RequestID is the ID of the HTTP request that caused the event, as
	// the router's request-ID middleware assigned it.
	RequestID string `json:"request_id,omitempty"`
}

// Store defines the interface for audit event storage.
type Store interface {
	// Record stores an audit event and returns its sequence number.
	Record(ctx context.Context, event *Event) (int64, error)

	// GetBySequence retrieves events starting from a sequence number.
	GetBySequence(ctx context.Context, fromSequence int64, limit int) ([]*Event, error)

	// GetByTimeRange retrieves events within a time range.
	GetByTimeRange(ctx context.Context, from, to time.Time, limit int) ([]*Event, error)

	// GetByActor retrieves events for a specific actor.
	GetByActor(ctx context.Context, actorID uuid.UUID, limit int) ([]*Event, error)

	// GetByResource retrieves events for a specific resource.
	GetByResource(ctx context.Context, resourceType string, resourceID uuid.UUID, limit int) ([]*Event, error)

	// GetLastSequence returns the last recorded sequence number.
	GetLastSequence(ctx context.Context) (int64, error)

	// Acknowledge marks events up to a sequence as acknowledged.
	Acknowledge(ctx context.Context, sequence int64) error

	// GetLastAcknowledged returns the last acknowledged sequence number.
	GetLastAcknowledged(ctx context.Context) (int64, error)
}

// Emitter defines the interface for emitting audit events.
type Emitter interface {
	// Emit records an audit event.
	Emit(ctx context.Context, event *Event) error
}

// StreamConfig holds configuration for audit streaming.
type StreamConfig struct {
	Enabled         bool
	Endpoint        string
	BearerToken     string // #nosec G117 - This is configuration, not a hardcoded secret
	BatchSize       int
	FlushIntervalMs int
}
