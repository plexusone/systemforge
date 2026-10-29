package systemauth

import (
	"net/http"
	"slices"
	"strings"

	"github.com/ory/fosite"
)

// authorizePrompt is the OIDC prompt parameter of an authorization request
// (OIDC Core 3.1.2.1).
type authorizePrompt struct {
	// none: show no login or consent page; answer login_required or
	// consent_required at the client's redirect URI instead.
	none bool
	// login: authenticate the user again even with a login session.
	login bool
	// consent: show the consent page even when consent is recorded or the
	// client is first-party.
	consent bool
}

// parsePrompt parses a space-separated prompt value. select_account is
// accepted and has no effect: a browser has one SystemAuth login session.
// An unknown value, or none with any other value, is invalid_request.
func parsePrompt(raw string) (authorizePrompt, error) {
	var p authorizePrompt
	values := strings.Fields(raw)
	for _, v := range values {
		switch v {
		case "none":
			p.none = true
		case "login":
			p.login = true
		case "consent":
			p.consent = true
		case "select_account":
		default:
			return authorizePrompt{}, fosite.ErrInvalidRequest.WithHintf("The prompt parameter has an unknown value %q.", v)
		}
	}
	if p.none && len(values) > 1 {
		return authorizePrompt{}, fosite.ErrInvalidRequest.WithHint("The prompt value none must not be combined with other values.")
	}
	return p, nil
}

// authorizeReturnURL is the authorization request URL to come back to
// after the login or consent page, with the given prompt values removed:
// the page has been shown, and asking for it again would loop. The URL is
// unchanged when it carries none of them.
func authorizeReturnURL(r *http.Request, drop ...string) string {
	q := r.URL.Query()
	values := strings.Fields(q.Get("prompt"))
	kept := slices.DeleteFunc(slices.Clone(values), func(v string) bool { return slices.Contains(drop, v) })
	if len(kept) == len(values) {
		return r.URL.String()
	}
	if len(kept) == 0 {
		q.Del("prompt")
	} else {
		q.Set("prompt", strings.Join(kept, " "))
	}
	u := *r.URL
	u.RawQuery = q.Encode()
	return u.String()
}
