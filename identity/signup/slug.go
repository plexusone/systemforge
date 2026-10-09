package signup

import (
	"crypto/rand"
	"fmt"
	"math/big"
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
	if !strings.ContainsFunc(strings.ToLower(name), func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
	}) {
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

// managedAdjectives and managedNouns are the word lists SlugForManaged draws
// from. They are fixed so the shape of a generated handle is stable.
var (
	managedAdjectives = []string{"quiet", "brave", "swift", "gentle", "bright", "calm", "clever", "lucky", "merry", "sunny", "witty", "bold"}
	managedNouns      = []string{"otter", "falcon", "maple", "comet", "willow", "harbor", "meadow", "lantern", "pebble", "river", "cedar", "robin"}
)

// SlugForManaged returns the base personal-organization slug for a managed
// principal (ADR-006 decision 2, ADR-009): the value its manager entered
// when there is one, else two words and a number such as "quiet-otter-42".
// A generated slug is random and never derived from an email address or any
// other fact about the person. Like SlugForLogin it is only a base; the
// caller resolves collisions and reserved names.
func SlugForManaged(entered string) string {
	if strings.TrimSpace(entered) != "" {
		return normalizeSlug(entered)
	}
	return fmt.Sprintf("%s-%s-%d",
		managedAdjectives[randIntn(len(managedAdjectives))],
		managedNouns[randIntn(len(managedNouns))],
		10+randIntn(90))
}

// randIntn returns a uniformly random int in [0, n).
func randIntn(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("signup: reading random bytes: %v", err)) // crypto/rand failure is unrecoverable
	}
	return int(v.Int64())
}
