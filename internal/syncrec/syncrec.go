// Package syncrec provides a recording authz.RelationshipSyncer for tests.
package syncrec

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/authz/noop"
)

// Recorder records the registration and application-role calls made to it. All other syncer
// methods are no-ops from the embedded noop syncer.
type Recorder struct {
	*noop.Syncer

	mu    sync.Mutex
	calls []string

	// Err, when set, is returned from the recorded methods.
	Err error
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
	return r.record("RemoveAppRole:%s:%s:%s:%s", principalID, orgID, application, role)
}

// RegisterPrincipal records the call.
func (r *Recorder) RegisterPrincipal(_ context.Context, principalID uuid.UUID) error {
	return r.record("RegisterPrincipal:%s", principalID)
}

// RegisterOrganization records the call.
func (r *Recorder) RegisterOrganization(_ context.Context, orgID, ownerID uuid.UUID) error {
	return r.record("RegisterOrganization:%s:%s", orgID, ownerID)
}
