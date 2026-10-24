// Package syncrec provides a recording authz.RelationshipSyncer for tests.
package syncrec

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
)

// Recorder records the calls made to it.
type Recorder struct {
	*noop.Syncer

	mu    sync.Mutex
	calls []string

	// Err, when set, is returned from every recorded method.
	Err error

	// RemoveErr, when set, is returned from the methods that remove a
	// relationship (Remove*, Unregister*, UpdateOrgMembership, and
	// SetPlatformAdmin with false), so a test can fail revocations while
	// grants succeed.
	RemoveErr error
}

// New returns an empty Recorder.
func New() *Recorder { return &Recorder{Syncer: noop.NewSyncer()} }

// Calls returns a copy of the recorded calls, formatted "Method:arg:arg".
func (r *Recorder) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *Recorder) record(format string, args ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, fmt.Sprintf(format, args...))
	return r.Err
}

// recordRemove records a call that removes a relationship.
func (r *Recorder) recordRemove(format string, args ...any) error {
	if err := r.record(format, args...); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.RemoveErr
}

// Reset clears the recorded calls.
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = nil
}

// AddOrgMembership records the call.
func (r *Recorder) AddOrgMembership(_ context.Context, principalID, orgID uuid.UUID, role string) error {
	return r.record("AddOrgMembership:%s:%s:%s", principalID, orgID, role)
}

// AddAppRole records the call.
func (r *Recorder) AddAppRole(_ context.Context, principalID, orgID uuid.UUID, application, role string) error {
	return r.record("AddAppRole:%s:%s:%s:%s", principalID, orgID, application, role)
}

// RemoveAppRole records the call.
func (r *Recorder) RemoveAppRole(_ context.Context, principalID, orgID uuid.UUID, application, role string) error {
	return r.recordRemove("RemoveAppRole:%s:%s:%s:%s", principalID, orgID, application, role)
}

// SetResourceGrant records the call.
func (r *Recorder) SetResourceGrant(_ context.Context, principalID uuid.UUID, ref authz.ResourceRef, role string) error {
	return r.record("SetResourceGrant:%s:%s:%s:%s:%s", principalID, ref.OrganizationID, ref.Type, ref.ID, role)
}

// RemoveResourceGrant records the call.
func (r *Recorder) RemoveResourceGrant(_ context.Context, principalID uuid.UUID, ref authz.ResourceRef) error {
	return r.recordRemove("RemoveResourceGrant:%s:%s:%s:%s", principalID, ref.OrganizationID, ref.Type, ref.ID)
}

// RemoveOrgMembership records the call.
func (r *Recorder) RemoveOrgMembership(_ context.Context, principalID, orgID uuid.UUID, role string) error {
	return r.recordRemove("RemoveOrgMembership:%s:%s:%s", principalID, orgID, role)
}

// RegisterPrincipal records the call.
func (r *Recorder) RegisterPrincipal(_ context.Context, principalID uuid.UUID) error {
	return r.record("RegisterPrincipal:%s", principalID)
}

// RegisterOrganization records the call.
func (r *Recorder) RegisterOrganization(_ context.Context, orgID, ownerID uuid.UUID) error {
	return r.record("RegisterOrganization:%s:%s", orgID, ownerID)
}

// UpdateOrgMembership records the call.
func (r *Recorder) UpdateOrgMembership(_ context.Context, principalID, orgID uuid.UUID, oldRole, newRole string) error {
	return r.recordRemove("UpdateOrgMembership:%s:%s:%s:%s", principalID, orgID, oldRole, newRole)
}

// UnregisterPrincipal records the call.
func (r *Recorder) UnregisterPrincipal(_ context.Context, principalID uuid.UUID) error {
	return r.recordRemove("UnregisterPrincipal:%s", principalID)
}

// UnregisterOrganization records the call.
func (r *Recorder) UnregisterOrganization(_ context.Context, orgID uuid.UUID) error {
	return r.recordRemove("UnregisterOrganization:%s", orgID)
}

// SetPlatformAdmin records the call.
func (r *Recorder) SetPlatformAdmin(_ context.Context, principalID uuid.UUID, isAdmin bool) error {
	if isAdmin {
		return r.record("SetPlatformAdmin:%s:true", principalID)
	}
	return r.recordRemove("SetPlatformAdmin:%s:false", principalID)
}

// AddPrincipalManager records the call.
func (r *Recorder) AddPrincipalManager(_ context.Context, managedID, managerID uuid.UUID, role string) error {
	return r.record("AddPrincipalManager:%s:%s:%s", managedID, managerID, role)
}

// RemovePrincipalManager records the call.
func (r *Recorder) RemovePrincipalManager(_ context.Context, managedID, managerID uuid.UUID, role string) error {
	return r.recordRemove("RemovePrincipalManager:%s:%s:%s", managedID, managerID, role)
}
