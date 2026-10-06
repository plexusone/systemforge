package relyingparty

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// VerifiedIdentity is a SystemAuth identity whose ID token (and UserInfo)
// passed verification.
type VerifiedIdentity struct {
	// Subject is the OIDC sub: the SystemAuth principal ID. Applications
	// store it as sf_principal_id.
	Subject string
	// Email is the SystemAuth-reported email.
	Email string
	// EmailVerified reports whether SystemAuth asserts Email is verified.
	EmailVerified bool
	// Name is the display name.
	Name string
	// Picture is the avatar URL.
	Picture string
}

// Principal is the application's local principal, as the relying-party
// layer sees it.
type Principal struct {
	// ID is the app-local principal ID.
	ID string
	// Type is the principal type (human, service, ...). Default "human".
	Type string
	// SFPrincipalID is the linked SystemAuth principal ID (the OIDC sub);
	// empty when not linked yet.
	SFPrincipalID string
	// Email is the principal's email.
	Email string
	// EmailVerified reports whether the app considers Email verified.
	EmailVerified bool
	// Name is the display name.
	Name string
	// AvatarURL is the avatar URL.
	AvatarURL string
	// Active reports whether the principal may sign in.
	Active bool
	// CreatedAt and UpdatedAt are record timestamps.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Membership is an organization membership of a principal.
type Membership struct {
	ID               string
	OrganizationID   string
	OrganizationName string
	OrganizationSlug string
	// Role is guest, member, admin, owner or platform_admin.
	Role     string
	JoinedAt time.Time
}

// PrincipalStore is the persistence port the relying-party layer needs. An
// application implements it over its own schema; with Ent, a principal
// entity using identity/ent/mixin.PrincipalMixin already has the
// sf_principal_id field that Principal.SFPrincipalID maps to.
type PrincipalStore interface {
	// FindBySubject returns the principal linked to the SystemAuth subject
	// (sf_principal_id), or ErrPrincipalNotFound.
	FindBySubject(ctx context.Context, subject string) (*Principal, error)

	// FindByEmail returns the principal with this email (case-insensitive),
	// or ErrPrincipalNotFound.
	FindByEmail(ctx context.Context, email string) (*Principal, error)

	// LinkSubject sets sf_principal_id on an existing principal. It returns
	// ErrSubjectLinked if the subject is already linked to a principal.
	LinkSubject(ctx context.Context, principalID, subject string) error

	// CreatePrincipal creates an active human principal linked to
	// identity.Subject, with a verified email. It returns ErrSubjectLinked
	// if the subject was linked concurrently and ErrEmailConflict if the
	// email is taken.
	CreatePrincipal(ctx context.Context, identity VerifiedIdentity) (*Principal, error)

	// RecordLogin refreshes profile fields from identity after a sign-in.
	RecordLogin(ctx context.Context, principalID string, identity VerifiedIdentity, at time.Time) error

	// GetPrincipal returns a principal by app-local ID, or
	// ErrPrincipalNotFound.
	GetPrincipal(ctx context.Context, id string) (*Principal, error)
}

// Organization memberships are not part of PrincipalStore: they come from
// a MembershipSource (see memberships.go). A store that also implements
// MembershipLister is used as the default source.

// ResolvePrincipal finds or creates the app-local principal for a verified
// SystemAuth identity, using the same account-linking rules as SystemAuth:
//
//  1. The subject (sf_principal_id) is the primary key: a linked principal
//     signs in regardless of its current email.
//  2. Otherwise a verified identity email links to an existing principal
//     whose own email is verified and that is not linked to another
//     SystemAuth principal.
//  3. Otherwise a new principal is created, which requires a verified
//     email.
//
// An unverified email never links to or creates a principal.
func ResolvePrincipal(ctx context.Context, store PrincipalStore, id VerifiedIdentity, now time.Time) (*Principal, error) {
	if id.Subject == "" {
		return nil, errors.New("relyingparty: identity requires a subject")
	}
	id.Email = strings.TrimSpace(id.Email)

	// Two attempts: the second covers a concurrent first login that won the
	// unique sf_principal_id constraint.
	for attempt := 0; attempt < 2; attempt++ {
		p, err := store.FindBySubject(ctx, id.Subject)
		switch {
		case err == nil:
			return finishLogin(ctx, store, p, id, now)
		case !errors.Is(err, ErrPrincipalNotFound):
			return nil, fmt.Errorf("relyingparty: finding principal by subject: %w", err)
		}

		if id.Email == "" || !id.EmailVerified {
			return nil, ErrEmailNotVerified
		}

		p, err = store.FindByEmail(ctx, id.Email)
		switch {
		case err == nil:
			if !p.EmailVerified || (p.SFPrincipalID != "" && p.SFPrincipalID != id.Subject) {
				return nil, ErrEmailConflict
			}
			if !p.Active {
				return nil, ErrPrincipalInactive
			}
			err = store.LinkSubject(ctx, p.ID, id.Subject)
			if errors.Is(err, ErrSubjectLinked) {
				continue
			}
			if err != nil {
				return nil, fmt.Errorf("relyingparty: linking subject: %w", err)
			}
			p.SFPrincipalID = id.Subject
			return finishLogin(ctx, store, p, id, now)
		case !errors.Is(err, ErrPrincipalNotFound):
			return nil, fmt.Errorf("relyingparty: finding principal by email: %w", err)
		}

		p, err = store.CreatePrincipal(ctx, id)
		if errors.Is(err, ErrSubjectLinked) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return finishLogin(ctx, store, p, id, now)
	}
	return nil, ErrSubjectLinked
}

func finishLogin(ctx context.Context, store PrincipalStore, p *Principal, id VerifiedIdentity, now time.Time) (*Principal, error) {
	if !p.Active {
		return nil, ErrPrincipalInactive
	}
	if err := store.RecordLogin(ctx, p.ID, id, now); err != nil {
		return nil, fmt.Errorf("relyingparty: recording login: %w", err)
	}
	return p, nil
}

// MemoryPrincipalStore is an in-memory PrincipalStore for development and
// tests.
type MemoryPrincipalStore struct {
	mu          sync.Mutex
	principals  map[string]*Principal
	bySubject   map[string]string
	byEmail     map[string]string
	memberships map[string][]Membership
	now         func() time.Time
}

// NewMemoryPrincipalStore creates an empty in-memory store.
func NewMemoryPrincipalStore() *MemoryPrincipalStore {
	return &MemoryPrincipalStore{
		principals:  map[string]*Principal{},
		bySubject:   map[string]string{},
		byEmail:     map[string]string{},
		memberships: map[string][]Membership{},
		now:         time.Now,
	}
}

// AddPrincipal seeds a principal (e.g. one created by the app's own signup).
// An empty ID is assigned.
func (s *MemoryPrincipalStore) AddPrincipal(p Principal) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.NewString()
	}
	if p.Type == "" {
		p.Type = "human"
	}
	key := strings.ToLower(p.Email)
	if key != "" {
		if _, ok := s.byEmail[key]; ok {
			return nil, ErrEmailConflict
		}
		s.byEmail[key] = p.ID
	}
	if p.SFPrincipalID != "" {
		if _, ok := s.bySubject[p.SFPrincipalID]; ok {
			return nil, ErrSubjectLinked
		}
		s.bySubject[p.SFPrincipalID] = p.ID
	}
	s.principals[p.ID] = &p
	cp := p
	return &cp, nil
}

// AddMembership adds an organization membership for a principal.
func (s *MemoryPrincipalStore) AddMembership(principalID string, m Membership) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[principalID]; !ok {
		return ErrPrincipalNotFound
	}
	if m.ID == "" {
		m.ID = uuid.NewString()
	}
	s.memberships[principalID] = append(s.memberships[principalID], m)
	return nil
}

func (s *MemoryPrincipalStore) copyOf(id string) (*Principal, error) {
	p, ok := s.principals[id]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	cp := *p
	return &cp, nil
}

// FindBySubject implements PrincipalStore.
func (s *MemoryPrincipalStore) FindBySubject(_ context.Context, subject string) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.bySubject[subject]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return s.copyOf(id)
}

// FindByEmail implements PrincipalStore.
func (s *MemoryPrincipalStore) FindByEmail(_ context.Context, email string) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byEmail[strings.ToLower(email)]
	if !ok {
		return nil, ErrPrincipalNotFound
	}
	return s.copyOf(id)
}

// LinkSubject implements PrincipalStore.
func (s *MemoryPrincipalStore) LinkSubject(_ context.Context, principalID, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.principals[principalID]
	if !ok {
		return ErrPrincipalNotFound
	}
	if _, ok := s.bySubject[subject]; ok {
		return ErrSubjectLinked
	}
	p.SFPrincipalID = subject
	p.UpdatedAt = s.now()
	s.bySubject[subject] = principalID
	return nil
}

// CreatePrincipal implements PrincipalStore.
func (s *MemoryPrincipalStore) CreatePrincipal(_ context.Context, id VerifiedIdentity) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.bySubject[id.Subject]; ok {
		return nil, ErrSubjectLinked
	}
	key := strings.ToLower(id.Email)
	if _, ok := s.byEmail[key]; ok {
		return nil, ErrEmailConflict
	}
	now := s.now()
	name := id.Name
	if name == "" {
		name = id.Email
	}
	p := &Principal{
		ID:            uuid.NewString(),
		Type:          "human",
		SFPrincipalID: id.Subject,
		Email:         id.Email,
		EmailVerified: true,
		Name:          name,
		AvatarURL:     id.Picture,
		Active:        true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	s.principals[p.ID] = p
	s.bySubject[id.Subject] = p.ID
	s.byEmail[key] = p.ID
	cp := *p
	return &cp, nil
}

// RecordLogin implements PrincipalStore: it refreshes name and avatar.
func (s *MemoryPrincipalStore) RecordLogin(_ context.Context, principalID string, id VerifiedIdentity, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.principals[principalID]
	if !ok {
		return ErrPrincipalNotFound
	}
	if id.Name != "" {
		p.Name = id.Name
	}
	if id.Picture != "" {
		p.AvatarURL = id.Picture
	}
	p.UpdatedAt = at
	return nil
}

// GetPrincipal implements PrincipalStore.
func (s *MemoryPrincipalStore) GetPrincipal(_ context.Context, id string) (*Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.copyOf(id)
}

// Memberships implements MembershipLister.
func (s *MemoryPrincipalStore) Memberships(_ context.Context, principalID string) ([]Membership, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.principals[principalID]; !ok {
		return nil, ErrPrincipalNotFound
	}
	out := make([]Membership, len(s.memberships[principalID]))
	copy(out, s.memberships[principalID])
	return out, nil
}

var (
	_ PrincipalStore   = (*MemoryPrincipalStore)(nil)
	_ MembershipLister = (*MemoryPrincipalStore)(nil)
)
