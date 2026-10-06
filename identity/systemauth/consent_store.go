package systemauth

import (
	"context"
	"sync"
)

// ConsentStore records which scopes a principal has granted to a client.
// SystemAuth consults it on /oauth/authorize when social login is enabled
// and skip_consent is off.
type ConsentStore interface {
	// HasConsent reports whether principalID has granted clientID every
	// scope in scopes.
	HasConsent(ctx context.Context, principalID, clientID string, scopes []string) (bool, error)

	// SaveConsent records that principalID granted clientID scopes, adding
	// to any scopes granted before.
	SaveConsent(ctx context.Context, principalID, clientID string, scopes []string) error

	// RevokeConsent removes every scope principalID granted clientID.
	RevokeConsent(ctx context.Context, principalID, clientID string) error
}

// MemoryConsentStore is an in-memory ConsentStore. Consents are lost on
// restart (users are asked again); use a shared store for multiple replicas.
type MemoryConsentStore struct {
	mu       sync.Mutex
	consents map[string]map[string]bool
}

// NewMemoryConsentStore creates an empty in-memory consent store.
func NewMemoryConsentStore() *MemoryConsentStore {
	return &MemoryConsentStore{consents: map[string]map[string]bool{}}
}

func consentKey(principalID, clientID string) string {
	return principalID + "\x00" + clientID
}

// HasConsent implements ConsentStore.
func (s *MemoryConsentStore) HasConsent(_ context.Context, principalID, clientID string, scopes []string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	granted, ok := s.consents[consentKey(principalID, clientID)]
	if !ok {
		return false, nil
	}
	for _, scope := range scopes {
		if !granted[scope] {
			return false, nil
		}
	}
	return true, nil
}

// SaveConsent implements ConsentStore.
func (s *MemoryConsentStore) SaveConsent(_ context.Context, principalID, clientID string, scopes []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := consentKey(principalID, clientID)
	granted, ok := s.consents[key]
	if !ok {
		granted = map[string]bool{}
		s.consents[key] = granted
	}
	for _, scope := range scopes {
		granted[scope] = true
	}
	return nil
}

// RevokeConsent implements ConsentStore.
func (s *MemoryConsentStore) RevokeConsent(_ context.Context, principalID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.consents, consentKey(principalID, clientID))
	return nil
}

var _ ConsentStore = (*MemoryConsentStore)(nil)
