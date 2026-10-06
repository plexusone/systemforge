package systemauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// ErrExternalIdentityExists is returned by PrincipalDirectory implementations
// when the (provider, subject) pair is already linked to a principal. The
// resolver treats it as a lost race and re-reads the existing link.
var ErrExternalIdentityExists = errors.New("systemauth: external identity already linked")

// LoginPrincipal is the view of a human Principal that social login needs.
type LoginPrincipal struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	DisplayName   string
	AvatarURL     string
	Active        bool
}

// ExternalLogin is a normalized, upstream-authenticated identity.
type ExternalLogin struct {
	// Provider is the upstream provider name (github, google).
	Provider string
	// Subject is the provider's stable user ID.
	Subject string
	// Email is the provider-reported email.
	Email string
	// EmailVerified reports whether the provider asserts Email is verified.
	EmailVerified bool
	// Name is the display name.
	Name string
	// AvatarURL is the profile picture URL.
	AvatarURL string
}

// PrincipalDirectory is the persistence port for social login. It works on
// Principal records (and their Human extension), never on legacy User rows.
type PrincipalDirectory interface {
	// FindByExternalIdentity returns the principal linked to (provider,
	// subject), or ErrPrincipalNotFound.
	FindByExternalIdentity(ctx context.Context, provider, subject string) (*LoginPrincipal, error)

	// FindByVerifiedEmail returns the human principal whose email matches
	// (case-insensitively) and is itself verified, or ErrPrincipalNotFound.
	FindByVerifiedEmail(ctx context.Context, email string) (*LoginPrincipal, error)

	// CreateFromExternal creates a human principal from login, with the
	// email marked verified, and links the external identity. It returns
	// ErrEmailConflict if the email is already taken, and
	// ErrExternalIdentityExists if the identity was linked concurrently.
	CreateFromExternal(ctx context.Context, login ExternalLogin) (*LoginPrincipal, error)

	// LinkExternalIdentity links login's identity to an existing principal.
	// It returns ErrExternalIdentityExists if already linked.
	LinkExternalIdentity(ctx context.Context, principalID uuid.UUID, login ExternalLogin) error

	// RecordLogin updates last-login bookkeeping and the provider-reported
	// email on the external identity.
	RecordLogin(ctx context.Context, principalID uuid.UUID, login ExternalLogin, at time.Time) error

	// GetPrincipal returns a principal by ID, or ErrPrincipalNotFound.
	GetPrincipal(ctx context.Context, id uuid.UUID) (*LoginPrincipal, error)
}

// ResolveExternalLogin finds or creates the principal for an upstream login
// using the canonical account-linking model:
//
//  1. The (provider, subject) link is the primary key: if it exists, that
//     principal signs in, regardless of the current email.
//  2. Otherwise a verified upstream email may link to an existing principal
//     whose own email is verified.
//  3. Otherwise a new principal is created, which requires a verified email.
//
// An unverified email never links to or creates an account.
func ResolveExternalLogin(ctx context.Context, dir PrincipalDirectory, login ExternalLogin, now time.Time) (*LoginPrincipal, error) {
	if login.Provider == "" || login.Subject == "" {
		return nil, errors.New("systemauth: external login requires provider and subject")
	}
	login.Email = strings.TrimSpace(login.Email)

	// Two attempts: the second covers a concurrent first login for the same
	// identity that won the unique (provider, subject) constraint.
	for attempt := 0; attempt < 2; attempt++ {
		p, err := dir.FindByExternalIdentity(ctx, login.Provider, login.Subject)
		switch {
		case err == nil:
			return finishLogin(ctx, dir, p, login, now)
		case !errors.Is(err, ErrPrincipalNotFound):
			return nil, fmt.Errorf("finding external identity: %w", err)
		}

		if login.Email == "" || !login.EmailVerified {
			return nil, ErrEmailNotVerified
		}

		p, err = dir.FindByVerifiedEmail(ctx, login.Email)
		switch {
		case err == nil:
			if !p.Active {
				return nil, ErrPrincipalInactive
			}
			err = dir.LinkExternalIdentity(ctx, p.ID, login)
			if errors.Is(err, ErrExternalIdentityExists) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("linking external identity: %w", err)
			}
			return finishLogin(ctx, dir, p, login, now)
		case !errors.Is(err, ErrPrincipalNotFound):
			return nil, fmt.Errorf("finding principal by email: %w", err)
		}

		p, err = dir.CreateFromExternal(ctx, login)
		if errors.Is(err, ErrExternalIdentityExists) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return finishLogin(ctx, dir, p, login, now)
	}
	return nil, ErrExternalIdentityExists
}

func finishLogin(ctx context.Context, dir PrincipalDirectory, p *LoginPrincipal, login ExternalLogin, now time.Time) (*LoginPrincipal, error) {
	if !p.Active {
		return nil, ErrPrincipalInactive
	}
	if err := dir.RecordLogin(ctx, p.ID, login, now); err != nil {
		return nil, fmt.Errorf("recording login: %w", err)
	}
	return p, nil
}

// MemoryPrincipalDirectory is an in-memory PrincipalDirectory for development
// and tests.
type MemoryPrincipalDirectory struct {
	mu         sync.Mutex
	principals map[uuid.UUID]*LoginPrincipal
	byEmail    map[string]uuid.UUID
	byExternal map[string]uuid.UUID
	lastLogin  map[uuid.UUID]time.Time
}

// NewMemoryPrincipalDirectory creates an empty in-memory directory.
func NewMemoryPrincipalDirectory() *MemoryPrincipalDirectory {
	return &MemoryPrincipalDirectory{
		principals: map[uuid.UUID]*LoginPrincipal{},
		byEmail:    map[string]uuid.UUID{},
		byExternal: map[string]uuid.UUID{},
		lastLogin:  map[uuid.UUID]time.Time{},
	}
}

func externalKey(provider, subject string) string { return provider + "\x00" + subject }

// AddPrincipal seeds a principal (e.g. one created by password signup).
func (d *MemoryPrincipalDirectory) AddPrincipal(p LoginPrincipal) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := strings.ToLower(p.Email)
	if _, ok := d.byEmail[key]; ok {
		return ErrEmailConflict
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	d.principals[p.ID] = &p
	d.byEmail[key] = p.ID
	return nil
}

// LastLogin returns the last recorded login time for a principal.
func (d *MemoryPrincipalDirectory) LastLogin(id uuid.UUID) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.lastLogin[id]
	return t, ok
}

func (d *MemoryPrincipalDirectory) copyOf(id uuid.UUID) (*LoginPrincipal, error) {
	p, ok := d.principals[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	cp := *p
	return &cp, nil
}

// FindByExternalIdentity implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) FindByExternalIdentity(_ context.Context, provider, subject string) (*LoginPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.byExternal[externalKey(provider, subject)]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return d.copyOf(id)
}

// FindByVerifiedEmail implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) FindByVerifiedEmail(_ context.Context, email string) (*LoginPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.byEmail[strings.ToLower(email)]
	if !ok || !d.principals[id].EmailVerified {
		return nil, ErrPrincipalNotFound
	}
	return d.copyOf(id)
}

// CreateFromExternal implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) CreateFromExternal(_ context.Context, login ExternalLogin) (*LoginPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.byExternal[externalKey(login.Provider, login.Subject)]; ok {
		return nil, ErrExternalIdentityExists
	}
	key := strings.ToLower(login.Email)
	if _, ok := d.byEmail[key]; ok {
		return nil, ErrEmailConflict
	}
	p := &LoginPrincipal{
		ID:            uuid.New(),
		Email:         login.Email,
		EmailVerified: true,
		DisplayName:   displayNameFor(login),
		AvatarURL:     login.AvatarURL,
		Active:        true,
	}
	d.principals[p.ID] = p
	d.byEmail[key] = p.ID
	d.byExternal[externalKey(login.Provider, login.Subject)] = p.ID
	cp := *p
	return &cp, nil
}

// LinkExternalIdentity implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) LinkExternalIdentity(_ context.Context, principalID uuid.UUID, login ExternalLogin) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.principals[principalID]; !ok {
		return ErrPrincipalNotFound
	}
	key := externalKey(login.Provider, login.Subject)
	if _, ok := d.byExternal[key]; ok {
		return ErrExternalIdentityExists
	}
	d.byExternal[key] = principalID
	return nil
}

// RecordLogin implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) RecordLogin(_ context.Context, principalID uuid.UUID, _ ExternalLogin, at time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.principals[principalID]; !ok {
		return ErrPrincipalNotFound
	}
	d.lastLogin[principalID] = at
	return nil
}

// GetPrincipal implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) GetPrincipal(_ context.Context, id uuid.UUID) (*LoginPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.copyOf(id)
}

var _ PrincipalDirectory = (*MemoryPrincipalDirectory)(nil)

func displayNameFor(login ExternalLogin) string {
	if login.Name != "" {
		return login.Name
	}
	if login.Email != "" {
		return login.Email
	}
	return login.Provider + ":" + login.Subject
}
