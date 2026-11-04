// Package weburl checks URLs that people store and other people's browsers
// load or follow: organization logos and websites, and avatars.
package weburl

import (
	"errors"
	"net/url"
	"strings"
)

// MaxLen is the longest URL accepted.
const MaxLen = 2048

// ErrNotHTTPS is returned for a URL that is not an absolute https URL.
var ErrNotHTTPS = errors.New("must be an absolute https URL")

// CheckHTTPS returns nil when raw is empty, which clears the field, or an
// absolute https URL with a host, no user info, no control characters and
// at most MaxLen bytes. Anything else, such as "javascript:", "data:" or
// "http:", returns ErrNotHTTPS: a stored URL is loaded or followed by every
// browser that shows it.
func CheckHTTPS(raw string) error {
	if raw == "" {
		return nil
	}
	if len(raw) > MaxLen || strings.ContainsAny(raw, "\\") {
		return ErrNotHTTPS
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ErrNotHTTPS
		}
	}
	u, err := url.Parse(raw)
	// u.Host is ":443" for "https://:443/x", which no browser can load, so
	// the host name itself must be present.
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil {
		return ErrNotHTTPS
	}
	return nil
}

// HTTPSOrEmpty returns raw when CheckHTTPS accepts it, and "" otherwise. Use
// it for values copied from an identity provider, where an unusable URL
// should be dropped rather than fail the sign-in.
func HTTPSOrEmpty(raw string) string {
	if CheckHTTPS(raw) != nil {
		return ""
	}
	return raw
}
