// Package serviceaccount manages service accounts: service principals that
// belong to one organization, hold application roles there like a member,
// and authenticate with key pairs through the RFC 7523 JWT-bearer grant
// (ADR-016).
//
// A service account is a Principal of type service whose organization_id
// is its organization, with a ServicePrincipal row of service type
// "service_account" and an active membership in the organization with the
// role "service_account". Its identifier, "sa_" and 26 random characters,
// is the issuer and subject of the assertions it signs. SystemAuth stores
// only its public keys, as key-pair credentials.
//
// Ending access goes through the usual paths and is recorded as an access
// change (ADR-010): Disable and Delete deactivate the principal
// (Deactivated), RemoveRole removes an application role (AppRoleChanged),
// and revoking a usable key records SessionsRevoked.
package serviceaccount

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/principal"
)

const (
	// MembershipRole is the membership role of a service account in its
	// organization, shown as "Service account".
	MembershipRole = "service_account"
	// ServiceType is the service type of a service account's
	// ServicePrincipal row.
	ServiceType = "service_account"
	// IdentifierPrefix starts every service account identifier.
	IdentifierPrefix = "sa_"
	// identifierRandomLength is the number of random characters after the
	// prefix (130 bits).
	identifierRandomLength = 26
)

// Errors returned by the service.
var (
	// ErrNotFound means the ID names no service account.
	ErrNotFound = errors.New("serviceaccount: service account not found")
	// ErrKeyNotFound means the account has no key with the key ID.
	ErrKeyNotFound = errors.New("serviceaccount: key not found")
	// ErrOrganizationNotFound means the organization does not exist.
	ErrOrganizationNotFound = errors.New("serviceaccount: organization not found")
	// ErrOrganizationInactive means the organization was deleted.
	ErrOrganizationInactive = errors.New("serviceaccount: organization is not active")
	// ErrPersonalOrganization means the organization is personal, and a
	// personal organization has no service accounts.
	ErrPersonalOrganization = errors.New("serviceaccount: a personal organization cannot have service accounts")
	// ErrNameRequired means CreateInput.Name is empty.
	ErrNameRequired = errors.New("serviceaccount: name is required")
	// ErrInvalidKey means a public key cannot be used: unparsable, of an
	// unsupported type or algorithm, an RSA key shorter than 2048 bits, or
	// an expiry in the past.
	ErrInvalidKey = errors.New("serviceaccount: invalid key")
)

// Account is a service account.
type Account struct {
	ID             uuid.UUID  `json:"id"`
	Identifier     string     `json:"identifier"`
	Name           string     `json:"name"`
	Description    string     `json:"description,omitempty"`
	OrganizationID uuid.UUID  `json:"organization_id"`
	Active         bool       `json:"active"`
	AllowedScopes  []string   `json:"allowed_scopes,omitempty"`
	CreatedBy      *uuid.UUID `json:"created_by,omitempty"`
	LastUsedAt     *time.Time `json:"last_used_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

// CreateInput describes a new service account.
type CreateInput struct {
	OrganizationID uuid.UUID
	Name           string
	Description    string
	// Scopes are the scopes the account may be granted; a token's scopes
	// are the requested ones intersected with these and its key's.
	Scopes []string
	// CreatedBy is the operator's principal ID; uuid.Nil records none.
	CreatedBy uuid.UUID
}

// PrincipalService is what the service needs of identity/principal.
// principal.DefaultService implements it.
type PrincipalService interface {
	principal.ServiceTxCreator
	Deactivate(ctx context.Context, id uuid.UUID) error
	Reactivate(ctx context.Context, id uuid.UUID) error
}

// Config holds the service's dependencies.
type Config struct {
	// Client is the identity database. Required.
	Client *ent.Client
	// Principals creates, deactivates and reactivates principals. Use the
	// host's principal service so authorization syncing and access-change
	// announcements follow its options. Required; principal.NewService's
	// result implements it.
	Principals principal.Service
	// Credentials stores key-pair credentials. Default:
	// credential.NewService(Client).
	Credentials credential.Service
	// Roles manages application roles. Required for GrantRole, RemoveRole
	// and Delete.
	Roles *approle.Service
	// AccessChangeSink announces the access changes the service itself
	// records (revoking a key) after they commit.
	AccessChangeSink accesschange.Sink
	// Logger records operator actions. Default: slog.Default().
	Logger *slog.Logger
}

// Service manages service accounts.
type Service struct {
	client      *ent.Client
	principals  PrincipalService
	credentials credential.Service
	roles       *approle.Service
	accessSink  accesschange.Sink
	logger      *slog.Logger
	now         func() time.Time
}

// New returns a Service. It fails when Client or Principals is missing, or
// when Principals cannot create a service principal in a transaction.
func New(cfg Config) (*Service, error) {
	if cfg.Client == nil {
		return nil, errors.New("serviceaccount: Config.Client is required")
	}
	principals, ok := cfg.Principals.(PrincipalService)
	if !ok {
		return nil, errors.New("serviceaccount: Config.Principals must implement principal.ServiceTxCreator")
	}
	s := &Service{
		client:      cfg.Client,
		principals:  principals,
		credentials: cfg.Credentials,
		roles:       cfg.Roles,
		accessSink:  cfg.AccessChangeSink,
		logger:      cfg.Logger,
		now:         time.Now,
	}
	if s.credentials == nil {
		s.credentials = credential.NewService(cfg.Client)
	}
	if s.logger == nil {
		s.logger = slog.Default()
	}
	return s, nil
}

// identifierAlphabet is lowercase RFC 4648 base32: 32 symbols, so a random
// byte masked to five bits picks one without bias.
const identifierAlphabet = "abcdefghijklmnopqrstuvwxyz234567"

// NewIdentifier returns a fresh service account identifier: "sa_" and 26
// random lowercase base32 characters.
func NewIdentifier() string {
	buf := make([]byte, identifierRandomLength)
	if _, err := rand.Read(buf); err != nil {
		// crypto/rand.Read never fails on supported platforms.
		panic("serviceaccount: reading random bytes: " + err.Error())
	}
	out := make([]byte, 0, len(IdentifierPrefix)+identifierRandomLength)
	out = append(out, IdentifierPrefix...)
	for _, b := range buf {
		out = append(out, identifierAlphabet[b&31])
	}
	return string(out)
}
