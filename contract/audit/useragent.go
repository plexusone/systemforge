package audit

import (
	"regexp"
	"strings"
)

// MaxUserAgent bounds the User-Agent an emitter records.
const MaxUserAgent = 512

var (
	// emailInText matches an email address anywhere in a string.
	emailInText = regexp.MustCompile(`[^\s@<>()"]+@[^\s@<>()"]+\.[A-Za-z]{2,}`)
	// credentialRun matches a long unbroken run of token characters, the
	// shape of a bearer token, JWT segment, API key or session ID. Browser
	// and library User-Agents have no run this long.
	credentialRun = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{32,}`)
)

// SanitizeUserAgent returns the User-Agent an emitter may record: the
// client sends it, so it can carry anything. A value that looks like it
// holds an email address or a credential is dropped (""), and any other is
// cut to MaxUserAgent bytes of valid UTF-8 without control characters.
func SanitizeUserAgent(ua string) string {
	if ua == "" || emailInText.MatchString(ua) || credentialRun.MatchString(ua) {
		return ""
	}
	if len(ua) > MaxUserAgent {
		ua = ua[:MaxUserAgent]
	}
	ua = strings.ToValidUTF8(ua, "")
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, ua)
}
