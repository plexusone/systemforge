package systemauth

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"github.com/plexusone/systemforge/session/ratelimit"
)

// SignupWaitlistPath serves the waitlist page an invite-only deployment
// sends refused sign-ups to: GET renders a notify-me form, POST records the
// address.
const SignupWaitlistPath = "/signup/waitlist"

// SignupWaitlist records an address that asked to be told when sign-up
// opens, with the consent text it was shown. It must not reveal whether the
// address was already listed.
type SignupWaitlist interface {
	Join(ctx context.Context, email, consentVersion, consentText string) error
}

// WaitlistPage is the waitlist page's wording. Empty fields take the
// defaults (DefaultWaitlistPage).
type WaitlistPage struct {
	// Title is the page heading.
	Title string
	// Message explains why sign-up is closed.
	Message string
	// RefusedNotice is shown after a refused sign-up.
	RefusedNotice string
	// ConsentText is what the person agrees to by submitting; it is
	// recorded with the address.
	ConsentText string
	// ConsentVersion identifies ConsentText; change it when the text
	// changes.
	ConsentVersion string
	// Thanks is shown after a submission.
	Thanks string
}

// DefaultWaitlistPage is the wording used for empty WaitlistPage fields.
var DefaultWaitlistPage = WaitlistPage{
	Title:          "Join the waitlist",
	Message:        "Sign-up is by invitation for now. Leave your email address and we will let you know when you can join.",
	RefusedNotice:  "There is no invitation for your account yet.",
	ConsentText:    "Use my email address only to tell me when I can sign up. I can ask for it to be removed at any time.",
	ConsentVersion: "1",
	Thanks:         "Thank you. We will email you when you can sign up.",
}

func (p WaitlistPage) withDefaults() WaitlistPage {
	d := DefaultWaitlistPage
	for _, f := range []struct{ v, def *string }{
		{&p.Title, &d.Title}, {&p.Message, &d.Message}, {&p.RefusedNotice, &d.RefusedNotice},
		{&p.ConsentText, &d.ConsentText}, {&p.ConsentVersion, &d.ConsentVersion}, {&p.Thanks, &d.Thanks},
	} {
		if *f.v == "" {
			*f.v = *f.def
		}
	}
	return p
}

// Default waitlist submission limits: per client address, and per submitted
// email address so one address cannot be resubmitted in a loop.
var (
	DefaultWaitlistAddressLimit = ratelimit.PerMinute(20)
	DefaultWaitlistEmailLimit   = ratelimit.PerHour(5)
)

// WithSignupWaitlist serves the waitlist page at SignupWaitlistPath with the
// given wording. With a sign-up gate and no WithSignupDeniedURL, refused
// sign-ups are sent there. Submissions are rate-limited with the login-token
// rate storage and client address function when those are set.
func WithSignupWaitlist(list SignupWaitlist, page WaitlistPage) Option {
	return func(s *Server) {
		s.socialOpts.waitlist = list
		s.socialOpts.waitlistPage = page.withDefaults()
	}
}

var waitlistTemplate = template.Must(template.New("waitlist").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Page.Title}}</title></head>
<body><main><h1>{{.Page.Title}}</h1>
{{if .Thanks}}<p role="status">{{.Page.Thanks}}</p>{{else}}
{{if .Refused}}<p role="status">{{.Page.RefusedNotice}}</p>{{end}}
<p>{{.Page.Message}}</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<label for="email">Email address</label>
<input id="email" name="email" type="email" autocomplete="email" required maxlength="320" value="{{.Email}}">
<label><input name="consent" type="checkbox" value="yes" required> {{.Page.ConsentText}}</label>
<button type="submit">Notify me</button>
</form>{{end}}
</main></body></html>
`))

type waitlistView struct {
	Page    WaitlistPage
	Action  string
	Refused bool
	Thanks  bool
	Error   string
	Email   string
}

func (sl *socialLogin) renderWaitlist(w http.ResponseWriter, r *http.Request, status int, v waitlistView) {
	v.Page, v.Action = sl.waitlistPage, SignupWaitlistPath
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := waitlistTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering waitlist page", "error", err)
	}
}

// handleWaitlistPage serves GET SignupWaitlistPath.
func (sl *socialLogin) handleWaitlistPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	sl.renderWaitlist(w, r, http.StatusOK, waitlistView{Refused: r.URL.Query().Get("error") == "invite_required"})
}

// handleWaitlistJoin serves POST SignupWaitlistPath. The answer is the same
// whether or not the address was already listed.
func (sl *socialLogin) handleWaitlistJoin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)
	if !sl.redirects.fromTrustedOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	if !plainEmail(email) {
		sl.renderWaitlist(w, r, http.StatusBadRequest, waitlistView{Error: "Enter a valid email address.", Email: email})
		return
	}
	if r.PostForm.Get("consent") != "yes" {
		sl.renderWaitlist(w, r, http.StatusBadRequest, waitlistView{Error: "Confirm how we may use your email address.", Email: email})
		return
	}
	address := sl.waitlistClientIP(r)
	if address == "" {
		address = "unknown"
	}
	for _, check := range []struct {
		key   string
		limit ratelimit.Limit
	}{
		{"waitlist:ip:" + address, DefaultWaitlistAddressLimit},
		{"waitlist:email:" + strings.ToLower(email), DefaultWaitlistEmailLimit},
	} {
		res, err := sl.waitlistRates.Allow(ctx, check.key, check.limit)
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
			logger.Error("waitlist rate limit", "error", err)
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if err := sl.waitlist.Join(ctx, email, sl.waitlistPage.ConsentVersion, sl.waitlistPage.ConsentText); err != nil {
		logger.Error("joining the waitlist", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("waitlist submission")
	sl.renderWaitlist(w, r, http.StatusOK, waitlistView{Thanks: true})
}

// plainEmail reports whether s is a bare address (no display name) with a
// dotted domain.
func plainEmail(s string) bool {
	if s == "" || len(s) > 320 {
		return false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address != s {
		return false
	}
	at := strings.LastIndex(s, "@")
	return at > 0 && strings.Contains(s[at+1:], ".")
}
