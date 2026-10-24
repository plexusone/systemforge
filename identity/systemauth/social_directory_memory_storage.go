package systemauth

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// PrincipalDirectory returns a social login directory that keeps its
// principals in s, so the principals social login creates are the ones
// SystemAuth checks when their tokens are used (PrincipalStatus). The
// server uses it by default with memory storage.
func (s *MemoryStorage) PrincipalDirectory() PrincipalDirectory {
	return memoryStorageDirectory{s: s}
}

// memoryStorageDirectory is a PrincipalDirectory over MemoryStorage.
type memoryStorageDirectory struct {
	s *MemoryStorage
}

// FindByExternalIdentity implements PrincipalDirectory.
func (d memoryStorageDirectory) FindByExternalIdentity(ctx context.Context, provider, subject string) (*HumanPrincipal, error) {
	return d.s.GetHumanByExternalIdentity(ctx, provider, subject)
}

// FindByVerifiedEmail implements PrincipalDirectory.
func (d memoryStorageDirectory) FindByVerifiedEmail(_ context.Context, email string) (*HumanPrincipal, error) {
	d.s.mu.RLock()
	defer d.s.mu.RUnlock()
	h, ok := d.s.humanByEmailLocked(email)
	if !ok || !h.EmailVerified {
		return nil, ErrPrincipalNotFound
	}
	return copyHuman(h), nil
}

// CreateFromExternal implements PrincipalDirectory.
func (d memoryStorageDirectory) CreateFromExternal(_ context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	key := externalKey(login.Provider, login.Subject)
	if _, ok := d.s.external[key]; ok {
		return nil, ErrExternalIdentityExists
	}
	if login.Email == "" {
		return nil, ErrEmailRequired
	}
	if _, ok := d.s.humanByEmailLocked(login.Email); ok {
		return nil, ErrEmailConflict
	}
	now := time.Now()
	h := &HumanPrincipal{
		ID:            uuid.New(),
		Email:         login.Email,
		EmailVerified: true,
		DisplayName:   displayNameFor(login),
		AvatarURL:     login.AvatarURL,
		Active:        true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	d.s.humans[h.ID] = h
	d.s.external[key] = h.ID
	return copyHuman(h), nil
}

// LinkExternalIdentity implements PrincipalDirectory.
func (d memoryStorageDirectory) LinkExternalIdentity(ctx context.Context, principalID uuid.UUID, login ExternalLogin) error {
	if p, err := d.s.GetHumanByExternalIdentity(ctx, login.Provider, login.Subject); err == nil && p.ID == principalID {
		return ErrExternalIdentityExists
	}
	return d.s.LinkExternalIdentity(ctx, principalID, login.Provider, login.Subject)
}

// RecordLogin implements PrincipalDirectory. Memory storage keeps no login
// history; it only checks the principal exists.
func (d memoryStorageDirectory) RecordLogin(ctx context.Context, principalID uuid.UUID, _ ExternalLogin, _ time.Time) error {
	_, err := d.s.GetHuman(ctx, principalID)
	return err
}

// GetPrincipal implements PrincipalDirectory.
func (d memoryStorageDirectory) GetPrincipal(ctx context.Context, id uuid.UUID) (*HumanPrincipal, error) {
	return d.s.GetHuman(ctx, id)
}

var _ PrincipalDirectory = memoryStorageDirectory{}
