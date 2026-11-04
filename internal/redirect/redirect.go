// Package redirect holds checks shared by the return_to validators.
package redirect

import (
	"net/url"
	"strings"
)

// PathIsPlain reports whether u's path is the path a browser will request:
// it has no "." or ".." segments, written plainly or percent-encoded, and
// does not decode to one starting with "//".
//
// A validator that checks the raw string and then hands it on is not enough
// on its own: "/.//evil.example" starts with a single slash, but a client
// that resolves it and rebuilds the URL from its path gets
// "//evil.example", which a browser reads as another host.
func PathIsPlain(u *url.URL) bool {
	if strings.HasPrefix(u.Path, "//") {
		return false
	}
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		s, err := url.PathUnescape(seg)
		if err != nil || s == "." || s == ".." {
			return false
		}
	}
	return true
}
