package signup

import (
	"strings"

	"github.com/plexusone/systemforge/identity/organization"
)

// Login providers whose handle rules SlugForLogin knows.
const (
	ProviderGitHub = "github"
	ProviderGoogle = "google"
)

// SlugForLogin derives the base personal-organization slug for a person who
// arrived through an upstream login (ADR-006 decision 2):
//
//   - github: the GitHub username (providerLogin);
//   - google: the local part of the email address, before "@";
//   - any other provider: providerLogin when set, else the email local part.
//
// When the preferred source is empty the other one is used. The result is
// always a valid organization slug (3 to 63 characters,
// ^[a-z][a-z0-9-]*[a-z0-9]$), but it is only a base: it may already be taken,
// and the caller resolves a collision with a numeric suffix against the
// organization table (see CreatePersonalOrgInTx). Managed-principal and
// reserved-slug rules are not part of this function.
func SlugForLogin(provider, providerLogin, email string) string {
	local := email
	if i := strings.IndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	first, second := providerLogin, local
	if provider == ProviderGoogle {
		first, second = local, providerLogin
	}
	name := strings.TrimSpace(first)
	if name == "" {
		name = strings.TrimSpace(second)
	}
	return normalizeSlug(name)
}

// normalizeSlug turns name into a valid slug. organization.Slugify leaves a
// leading digit alone, which the slug rules refuse, so such a slug is
// prefixed with "u-"; an empty name becomes "user".
func normalizeSlug(name string) string {
	if name == "" {
		name = "user"
	}
	slug := organization.Slugify(name)
	if slug == "" || slug[0] < 'a' || slug[0] > 'z' {
		slug = organization.Slugify("u-" + slug)
	}
	if !organization.IsValidSlug(slug) {
		slug = "user"
		if !organization.IsValidSlug(slug) {
			panic("signup: fallback slug is invalid") // programming error
		}
	}
	return slug
}
