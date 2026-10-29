package systemauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// ErrExternalIdentityExists is returned by PrincipalDirectory implementations
// when the (provider, subject) pair is already linked to a principal. The
// resolver treats it as a lost race and re-reads the existing link.
var ErrExternalIdentityExists = errors.New("systemauth: external identity already linked")

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
	// EmailAuthoritative reports whether the provider is authoritative for
	// Email: it controls the address now, not only when it was verified.
	// Only an authoritative email links a new identity to an existing
	// account; see AuthoritativeEmail.
	EmailAuthoritative bool
	// EmailProven reports that SystemAuth itself verified Email in this
	// sign-in: the person opened a verification link mailed to it, in the
	// browser that started the sign-in (ADR-003). Proven control of the
	// mailbox counts as verified and as authoritative, so the login may
	// create an account or link to an existing one with that verified
	// email, as an authoritative provider email does.
	EmailProven bool
	// Name is the display name.
	Name string
	// Username is the provider's handle for the person (the GitHub login),
	// when it has one. It seeds the personal organization's slug.
	Username string
	// AvatarURL is the profile picture URL.
	AvatarURL string
}

// PrincipalDirectory is the persistence port for social login. It works on
// Principal records (and their Human extension), never on legacy User rows.
type PrincipalDirectory interface {
	// FindByExternalIdentity returns the principal linked to (provider,
	// subject), or ErrPrincipalNotFound.
	FindByExternalIdentity(ctx context.Context, provider, subject string) (*HumanPrincipal, error)

	// FindByVerifiedEmail returns the human principal whose email matches
	// (case-insensitively) and is itself verified, or ErrPrincipalNotFound.
	FindByVerifiedEmail(ctx context.Context, email string) (*HumanPrincipal, error)

	// CreateFromExternal creates a human principal from login, with the
	// email marked verified, and links the external identity. An
	// implementation backed by an organization store also creates the
	// person's personal organization in the same transaction (ADR-006
	// decision 1), so a first login yields both or nothing. It returns
	// ErrEmailConflict if the email is already taken, and
	// ErrExternalIdentityExists if the identity was linked concurrently.
	CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error)

	// LinkExternalIdentity links login's identity to an existing principal.
	// It returns ErrExternalIdentityExists if already linked.
	LinkExternalIdentity(ctx context.Context, principalID uuid.UUID, login ExternalLogin) error

	// RecordLogin updates last-login bookkeeping and the provider-reported
	// email on the external identity.
	RecordLogin(ctx context.Context, principalID uuid.UUID, login ExternalLogin, at time.Time) error

	// GetPrincipal returns a principal by ID, or ErrPrincipalNotFound.
	GetPrincipal(ctx context.Context, id uuid.UUID) (*HumanPrincipal, error)
}

// ResolveExternalLogin finds or creates the principal for an upstream login
// using the canonical account-linking model:
//
//  1. The (provider, subject) link is the primary key: if it exists, that
//     principal signs in, regardless of the current email.
//  2. Otherwise an authoritative upstream email (EmailAuthoritative) may
//     link to an existing principal whose own email is verified.
//  3. Otherwise a new principal is created, which requires a verified email;
//     an email that already belongs to a principal gives ErrEmailConflict,
//     and the person signs in with the method they used before.
//
// A proven email (EmailProven) counts as verified and authoritative: the
// person just showed control of the mailbox. Otherwise an unverified email
// never links to or creates an account. A verified but not authoritative
// email never links: a provider can keep an address marked
// verified after its owner loses the mailbox, so linking on it would hand the
// existing account to whoever holds the stale verification.
func ResolveExternalLogin(ctx context.Context, dir PrincipalDirectory, login ExternalLogin, now time.Time) (*HumanPrincipal, error) {
	if login.Provider == "" || login.Subject == "" {
		return nil, errors.New("systemauth: external login requires provider and subject")
	}
	login.Email = strings.TrimSpace(login.Email)
	if login.EmailProven && login.Email != "" {
		login.EmailVerified, login.EmailAuthoritative = true, true
	}

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
		if !login.EmailAuthoritative {
			p, err = dir.CreateFromExternal(ctx, login)
			if errors.Is(err, ErrExternalIdentityExists) {
				continue
			}
			if err != nil {
				return nil, err
			}
			return finishLogin(ctx, dir, p, login, now)
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

// PersonalOrgEnsurer is implemented by directories that keep personal
// organizations. ResolveExternalLogin calls it on every successful login.
type PersonalOrgEnsurer interface {
	// EnsurePersonalOrg creates the principal's personal organization when
	// it has none and does nothing otherwise.
	EnsurePersonalOrg(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error
}

func finishLogin(ctx context.Context, dir PrincipalDirectory, p *HumanPrincipal, login ExternalLogin, now time.Time) (*HumanPrincipal, error) {
	if !p.Active {
		return nil, ErrPrincipalInactive
	}
	if err := dir.RecordLogin(ctx, p.ID, login, now); err != nil {
		return nil, fmt.Errorf("recording login: %w", err)
	}
	// Backfill: a principal created before signup-on-first-login (or linked
	// by verified email) may have no personal organization. Giving it one on
	// its next login is idempotent, so repeat logins create nothing.
	if e, ok := dir.(PersonalOrgEnsurer); ok {
		if err := e.EnsurePersonalOrg(ctx, p, login); err != nil {
			return nil, fmt.Errorf("ensuring personal organization: %w", err)
		}
	}
	return p, nil
}

// MemoryPrincipalDirectory is an in-memory PrincipalDirectory for development
// and tests.
type MemoryPrincipalDirectory struct {
	mu         sync.Mutex
	principals map[uuid.UUID]*HumanPrincipal
	byEmail    map[string]uuid.UUID
	byExternal map[string]uuid.UUID
	lastLogin  map[uuid.UUID]time.Time
}

// NewMemoryPrincipalDirectory creates an empty in-memory directory.
func NewMemoryPrincipalDirectory() *MemoryPrincipalDirectory {
	return &MemoryPrincipalDirectory{
		principals: map[uuid.UUID]*HumanPrincipal{},
		byEmail:    map[string]uuid.UUID{},
		byExternal: map[string]uuid.UUID{},
		lastLogin:  map[uuid.UUID]time.Time{},
	}
}

func externalKey(provider, subject string) string { return provider + "\x00" + subject }

// AddPrincipal seeds a principal (e.g. one created by password signup).
func (d *MemoryPrincipalDirectory) AddPrincipal(p HumanPrincipal) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	key := strings.ToLower(p.Email)
	if key != "" {
		if _, ok := d.byEmail[key]; ok {
			return ErrEmailConflict
		}
	}
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	d.principals[p.ID] = &p
	// A managed principal has no email to find it by.
	if key != "" {
		d.byEmail[key] = p.ID
	}
	return nil
}

// LastLogin returns the last recorded login time for a principal.
func (d *MemoryPrincipalDirectory) LastLogin(id uuid.UUID) (time.Time, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.lastLogin[id]
	return t, ok
}

func (d *MemoryPrincipalDirectory) copyOf(id uuid.UUID) (*HumanPrincipal, error) {
	p, ok := d.principals[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	cp := *p
	return &cp, nil
}

// FindByExternalIdentity implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) FindByExternalIdentity(_ context.Context, provider, subject string) (*HumanPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.byExternal[externalKey(provider, subject)]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return d.copyOf(id)
}

// FindByVerifiedEmail implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) FindByVerifiedEmail(_ context.Context, email string) (*HumanPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	id, ok := d.byEmail[strings.ToLower(email)]
	if !ok || email == "" || !d.principals[id].EmailVerified {
		return nil, ErrPrincipalNotFound
	}
	return d.copyOf(id)
}

// CreateFromExternal implements PrincipalDirectory.
func (d *MemoryPrincipalDirectory) CreateFromExternal(_ context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.byExternal[externalKey(login.Provider, login.Subject)]; ok {
		return nil, ErrExternalIdentityExists
	}
	key := strings.ToLower(login.Email)
	if _, ok := d.byEmail[key]; ok {
		return nil, ErrEmailConflict
	}
	p := &HumanPrincipal{
		ID:              uuid.New(),
		Email:           login.Email,
		EmailVerified:   true,
		EmailVerifiedAt: time.Now(),
		DisplayName:     displayNameFor(login),
		AvatarURL:       login.AvatarURL,
		Active:          true,
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
func (d *MemoryPrincipalDirectory) GetPrincipal(_ context.Context, id uuid.UUID) (*HumanPrincipal, error) {
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

// consumerGoogleDomains are the domains whose addresses only Google issues.
var consumerGoogleDomains = map[string]bool{"gmail.com": true, "googlemail.com": true}

// AuthoritativeEmail reports whether an upstream user's provider is
// authoritative for its verified email: it controls the address now, so the
// address identifies the person. Google is authoritative for its consumer
// domains and for a Workspace account's own domain (the `hd` claim). GitHub
// and other providers are not: they keep an address marked verified after
// the person loses the mailbox.
func AuthoritativeEmail(user *oauthclient.User) bool {
	if user == nil || !user.EmailVerified || user.Provider != oauthclient.ProviderGoogle {
		return false
	}
	at := strings.LastIndexByte(user.Email, '@')
	if at < 0 || at == len(user.Email)-1 {
		return false
	}
	domain := strings.ToLower(user.Email[at+1:])
	if consumerGoogleDomains[domain] {
		return true
	}
	return user.HostedDomain != "" && strings.EqualFold(user.HostedDomain, domain)
}
