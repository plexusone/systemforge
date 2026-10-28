package systemauth

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plexusone/systemforge/session/ratelimit"
)

// signupCodeCookie holds the invite code a person brought, between the
// sign-up page (or a provider start link) and the upstream callback.
const signupCodeCookie = "__Host-sf_signup_code"

// signupCodeTTL is how long the invite code cookie lasts: long enough to
// sign in upstream and answer the age question, short enough not to linger.
const signupCodeTTL = time.Hour

// inviteCodeParam is the query parameter on GET /login/{provider} that
// carries an invite code.
const inviteCodeParam = "invite_code"

// DefaultSignupPageLimit limits GET SignupPath per client address, so codes
// cannot be guessed through the page.
var DefaultSignupPageLimit = ratelimit.PerMinute(30)

// SignupCodeLookup checks an invite code a person brought. It returns the
// code in its stored form and whether it can still be used. It is
// implemented by signupgate.CodeStore.
type SignupCodeLookup interface {
	SignupCodeUsable(ctx context.Context, code string) (normalized string, usable bool, err error)
}

// SignupPage is the sign-up page's wording and where it sends people after
// they sign in. Empty wording fields take the defaults (DefaultSignupPage).
type SignupPage struct {
	// Title is the page heading.
	Title string
	// Message is shown with a valid invite, above the sign-in choices.
	Message string
	// InvalidNotice is shown for a code that cannot be used, whatever the
	// reason.
	InvalidNotice string
	// ReturnTo is where a person lands after signing in, such as the
	// application's sign-in URL. It must pass the same checks as return_to;
	// empty means the default redirect.
	ReturnTo string
}

// DefaultSignupPage is the wording used for empty SignupPage fields.
var DefaultSignupPage = SignupPage{
	Title:         "You're invited",
	Message:       "Sign in to create your account.",
	InvalidNotice: "This invite link is not valid. It may have been used up, expired or been revoked.",
}

func (p SignupPage) withDefaults() SignupPage {
	d := DefaultSignupPage
	for _, f := range []struct{ v, def *string }{
		{&p.Title, &d.Title}, {&p.Message, &d.Message}, {&p.InvalidNotice, &d.InvalidNotice},
	} {
		if *f.v == "" {
			*f.v = *f.def
		}
	}
	return p
}

// WithSignupCodes serves the sign-up page at SignupPath and accepts
// invite_code on GET /login/{provider}. A valid code is kept in a cookie for
// an hour and handed to the sign-up gate with WithSignupCode when the
// person's upstream login comes back. The page is rate-limited with the
// login-token rate storage and client address function when those are set.
func WithSignupCodes(lookup SignupCodeLookup, page SignupPage) Option {
	return func(s *Server) {
		s.socialOpts.signupCodes = lookup
		s.socialOpts.signupPage = page.withDefaults()
	}
}

// signupCookieName drops the __Host- prefix when the login runs over plain
// HTTP, as for the other login cookies.
func (sl *socialLogin) signupCookieName() string {
	if sl.cookies.secure {
		return signupCodeCookie
	}
	return strings.TrimPrefix(signupCodeCookie, hostCookiePrefix)
}

func (sl *socialLogin) setSignupCode(w http.ResponseWriter, normalized string) {
	http.SetCookie(w, sl.cookies.cookie(sl.signupCookieName(), normalized, int(signupCodeTTL.Seconds())))
}

func (sl *socialLogin) clearSignupCode(w http.ResponseWriter, r *http.Request) {
	if cookieValue(r, sl.signupCookieName()) != "" {
		http.SetCookie(w, sl.cookies.cookie(sl.signupCookieName(), "", -1))
	}
}

// withSignupCode returns ctx carrying the invite code cookie, if any.
func (sl *socialLogin) withSignupCode(ctx context.Context, r *http.Request) context.Context {
	if sl.signupCodes == nil {
		return ctx
	}
	return WithSignupCode(ctx, cookieValue(r, sl.signupCookieName()))
}

// keepInviteCode sets the invite code cookie from GET /login/{provider}'s
// invite_code parameter when the code can be used. An unusable code is
// ignored: the gate refuses the sign-up later if nothing else admits it.
func (sl *socialLogin) keepInviteCode(w http.ResponseWriter, r *http.Request) error {
	raw := r.URL.Query().Get(inviteCodeParam)
	if sl.signupCodes == nil || raw == "" {
		return nil
	}
	normalized, ok, err := sl.signupCodes.SignupCodeUsable(r.Context(), raw)
	if err != nil {
		return fmt.Errorf("checking invite code: %w", err)
	}
	if ok {
		sl.setSignupCode(w, normalized)
	}
	return nil
}

var signupCodeTemplate = template.Must(template.New("signup").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Page.Title}}</title></head>
<body><main><h1>{{.Page.Title}}</h1>
{{if .Invalid}}<p role="alert">{{.Page.InvalidNotice}}</p>
{{if .WaitlistURL}}<p><a href="{{.WaitlistURL}}">Join the waitlist</a></p>{{end}}
{{else}}<p>{{.Page.Message}}</p><ul>
{{range .Links}}<li><a href="{{.URL}}">Continue with {{.Name}}</a></li>
{{end}}</ul>{{end}}
</main></body></html>
`))

type signupLink struct{ Name, URL string }

type signupView struct {
	Page        SignupPage
	Invalid     bool
	WaitlistURL string
	Links       []signupLink
}

// handleSignupPage serves GET SignupPath?code=…. The page never says why a
// code cannot be used, and sends no referrer, so the code in its URL does
// not leak to the provider.
func (sl *socialLogin) handleSignupPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	noStore(w)
	address := sl.waitlistClientIP(r)
	if address == "" {
		address = "unknown"
	}
	res, err := sl.waitlistRates.Allow(ctx, "signup:ip:"+address, DefaultSignupPageLimit)
	if errors.Is(err, ratelimit.ErrTooManyKeys) || (err == nil && !res.Allowed) {
		retry := 60
		if err == nil {
			retry = int(res.RetryAfter.Seconds()) + 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if err != nil {
		LoggerFromContext(ctx).Error("sign-up page rate limit", "error", err)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
		return
	}

	v := signupView{Page: sl.signupPage}
	normalized, ok, err := sl.signupCodes.SignupCodeUsable(ctx, r.URL.Query().Get("code"))
	if err != nil {
		LoggerFromContext(ctx).Error("checking invite code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ok {
		sl.setSignupCode(w, normalized)
		for _, p := range sl.providers {
			name := providerDisplayNames[p]
			if name == "" {
				name = p
			}
			v.Links = append(v.Links, signupLink{Name: name, URL: startURL(p, sl.signupPage.ReturnTo)})
		}
	} else {
		v.Invalid = true
		if sl.waitlist != nil {
			v.WaitlistURL = SignupWaitlistPath
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := signupCodeTemplate.Execute(w, v); err != nil {
		LoggerFromContext(ctx).Error("rendering sign-up page", "error", err)
	}
}
