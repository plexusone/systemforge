package clientassertion

import (
	"context"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// MemoryJTIStore tracks used client-assertion JWT IDs in memory, with the
// same semantics as JTIStore. It suits a single instance; replicas need
// the database-backed store, since a replayed assertion can reach any of
// them.
type MemoryJTIStore struct {
	mu   sync.Mutex
	used map[string]time.Time
	now  func() time.Time
}

// NewMemoryJTIStore returns an empty MemoryJTIStore.
func NewMemoryJTIStore() *MemoryJTIStore {
	return &MemoryJTIStore{used: map[string]time.Time{}, now: time.Now}
}

// Valid returns fosite.ErrJTIKnown when jti has been used and has not yet
// expired, and nil otherwise.
func (s *MemoryJTIStore) Valid(_ context.Context, jti string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if exp, ok := s.used[jti]; ok && exp.After(s.now()) {
		return fosite.ErrJTIKnown
	}
	return nil
}

// Mark records jti as used until exp, first forgetting JTIs that have
// expired. Marking a JTI that is still live returns fosite.ErrJTIKnown.
func (s *MemoryJTIStore) Mark(_ context.Context, jti string, exp time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, e := range s.used {
		if !e.After(now) {
			delete(s.used, id)
		}
	}
	if _, ok := s.used[jti]; ok {
		return fosite.ErrJTIKnown
	}
	s.used[jti] = exp
	return nil
}
