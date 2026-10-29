package systemauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ClientParty says who owns an OAuth client relative to the data it reads.
// The customer owns the data in every case; the party decides whether the
// customer's users are asked for consent.
type ClientParty string

const (
	// PartyFirst is an application the service provider (the operator of
	// this SystemAuth deployment) owns. Its users are not asked for
	// consent: the application and the identity service are one product.
	PartyFirst ClientParty = "first_party"

	// PartySecond is an application the customer owns, such as an
	// integration a customer builds against its own tenant. Its users are
	// asked for consent, and the consent is recorded.
	PartySecond ClientParty = "second_party"

	// PartyThird is an application a partner owns. Its users are asked for
	// consent, and the consent is recorded. It is the party of a client
	// registered at runtime without one.
	PartyThird ClientParty = "third_party"
)

// ErrInvalidClientParty is returned for a party other than first_party,
// second_party or third_party.
var ErrInvalidClientParty = errors.New("systemauth: invalid client party (want first_party, second_party or third_party)")

// ErrInvalidClientLogoURL is returned for a client logo URL that is not an
// absolute https URL.
var ErrInvalidClientLogoURL = errors.New("systemauth: client logo_url must be an absolute https URL")

// Validate reports ErrInvalidClientParty for an unknown party. The empty
// party is valid and means PartyThird.
func (p ClientParty) Validate() error {
	switch p {
	case "", PartyFirst, PartySecond, PartyThird:
		return nil
	}
	return fmt.Errorf("%w: %q", ErrInvalidClientParty, string(p))
}

// Effective returns the party, with the empty party read as PartyThird:
// a client that does not say who owns it is treated as the least trusted.
func (p ClientParty) Effective() ClientParty {
	if p == "" {
		return PartyThird
	}
	return p
}

// EffectiveParty returns the client's party, PartyThird when unset.
func (c *Client) EffectiveParty() ClientParty {
	return c.Party.Effective()
}

// IsFirstParty reports whether the client is a first-party application,
// whose users are not asked for consent.
func (c *Client) IsFirstParty() bool {
	return c.EffectiveParty() == PartyFirst
}

// ValidateClientLogoURL checks a client logo URL: empty, or an absolute
// https URL without credentials. The login page shows it in an img element.
func ValidateClientLogoURL(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.User != nil || u.Opaque != "" {
		return ErrInvalidClientLogoURL
	}
	return nil
}

// validateClientMetadata checks the party and the logo URL of a client.
func validateClientMetadata(c *Client) error {
	if err := c.Party.Validate(); err != nil {
		return fmt.Errorf("client %q: %w", c.ID, err)
	}
	if err := ValidateClientLogoURL(c.LogoURL); err != nil {
		return fmt.Errorf("client %q: %w", c.ID, err)
	}
	return nil
}
