// Package noop provides a no-operation authorization syncer for deployments
// that don't require authorization backend synchronization.
package noop

import (
	"context"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
)

// Syncer is a no-operation implementation of RelationshipSyncer.
// All methods succeed without performing any action.
type Syncer struct{}

// NewSyncer creates a new no-op syncer.
func NewSyncer() *Syncer {
	return &Syncer{}
}

// AddOrgMembership is a no-op.
func (s *Syncer) AddOrgMembership(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

// RemoveOrgMembership is a no-op.
func (s *Syncer) RemoveOrgMembership(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

// UpdateOrgMembership is a no-op.
func (s *Syncer) UpdateOrgMembership(_ context.Context, _, _ uuid.UUID, _, _ string) error {
	return nil
}

// RegisterPrincipal is a no-op.
func (s *Syncer) RegisterPrincipal(_ context.Context, _ uuid.UUID) error {
	return nil
}

// UnregisterPrincipal is a no-op.
func (s *Syncer) UnregisterPrincipal(_ context.Context, _ uuid.UUID) error {
	return nil
}

// RegisterOrganization is a no-op.
func (s *Syncer) RegisterOrganization(_ context.Context, _, _ uuid.UUID) error {
	return nil
}

// UnregisterOrganization is a no-op.
func (s *Syncer) UnregisterOrganization(_ context.Context, _ uuid.UUID) error {
	return nil
}

// SetPlatformAdmin is a no-op.
func (s *Syncer) SetPlatformAdmin(_ context.Context, _ uuid.UUID, _ bool) error {
	return nil
}

// AddPrincipalManager is a no-op.
func (s *Syncer) AddPrincipalManager(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

// RemovePrincipalManager is a no-op.
func (s *Syncer) RemovePrincipalManager(_ context.Context, _, _ uuid.UUID, _ string) error {
	return nil
}

// Verify interface compliance at compile time.
var _ authz.RelationshipSyncer = (*Syncer)(nil)
