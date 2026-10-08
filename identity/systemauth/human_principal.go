package systemauth

import (
	"time"

	"github.com/google/uuid"
)

// HumanPrincipal is a human Principal joined with its Human extension. It is
// the single view of a person used by password login, social login, and
// federation sync.
type HumanPrincipal struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	DisplayName   string
	GivenName     string
	FamilyName    string
	AvatarURL     string
	Locale        string
	Active        bool
	Metadata      map[string]any
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// FederationProvider is the ExternalIdentity provider name recorded for
// identities synced from a federation hub; the federation's identity ID is
// the subject.
const FederationProvider = "systemauth-federation"
