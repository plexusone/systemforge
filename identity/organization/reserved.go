package organization

import (
	"errors"
	"strings"
)

// ErrSlugReserved is returned when a slug is on the reserved list: a name
// that would collide with a route, a protocol path or a product name.
var ErrSlugReserved = errors.New("slug is reserved")

// ReservedSlugs is the built-in list of slugs no organization may take.
// Deployments add their own product names with WithReservedSlugs. Entries
// shorter than the three-character minimum are kept so the list still
// documents the names that are refused.
var ReservedSlugs = []string{
	"about", "admin", "api", "help", "invites", "login", "logout", "new",
	"o", "oauth", "organizations", "scim", "settings", "support",
	"well-known", "www",
}

var builtinReserved = toSet(ReservedSlugs)

func toSet(slugs []string) map[string]struct{} {
	m := make(map[string]struct{}, len(slugs))
	for _, s := range slugs {
		m[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
	}
	return m
}

// IsReservedSlug reports whether slug is on the built-in reserved list.
// Use a service built with WithReservedSlugs to also consult
// deployment-configured names.
func IsReservedSlug(slug string) bool {
	_, ok := builtinReserved[strings.ToLower(slug)]
	return ok
}

// WithReservedSlugs adds deployment-configured slugs (for example product
// names) to the built-in reserved list.
func WithReservedSlugs(slugs ...string) ServiceOption {
	return func(s *DefaultService) {
		if s.reserved == nil {
			s.reserved = make(map[string]struct{})
		}
		for k := range toSet(slugs) {
			s.reserved[k] = struct{}{}
		}
	}
}

// isReserved reports whether slug is reserved for this service.
func (s *DefaultService) isReserved(slug string) bool {
	if IsReservedSlug(slug) {
		return true
	}
	_, ok := s.reserved[strings.ToLower(slug)]
	return ok
}
