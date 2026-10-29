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

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// SignupAgePath serves the age question a deployment with a minimum
// sign-up age asks before it creates an account: GET renders it, POST
// answers it.
const SignupAgePath = "/signup/age"

// errSignupAgeRequired is returned by the age-checked directory when an
// upstream login would create an account whose holder has not yet stated
// their age. The callback turns it into the age question; nothing about
// the login is kept.
var errSignupAgeRequired = errors.New("systemauth: sign-up needs the age question answered")

// Markers in the Nonce of login-state entries the age question keeps, so a
// pending question cannot be used as a confirmation or as upstream state.
const (
	signupAgePending   = "signup-age:pending"
	signupAgeConfirmed = "signup-age:confirmed"
)

// Lifetimes of the age question's entries and cookies.
const (
	// signupAgePendingTTL is how long a person has to answer.
	signupAgePendingTTL = 15 * time.Minute
	// signupAgeConfirmedTTL is how long a confirmed answer waits for the
	// upstream login it restarts.
	signupAgeConfirmedTTL = 10 * time.Minute
	// signupAgeRefusedTTL is how long a refused browser is not asked again.
	signupAgeRefusedTTL = 24 * time.Hour
)

// Age question cookie names: the hardened __Host- names, and plain names
// for InsecureCookies.
const (
	signupAgePendingCookie   = "__Host-sf_signup_age"
	signupAgeConfirmedCookie = "__Host-sf_signup_age_ok"
	signupAgeRefusedCookie   = "__Host-sf_signup_age_refused"
	hostCookiePrefix         = "__Host-"
)

// maxAgeAnswer is the oldest age the question offers.
const maxAgeAnswer = 120

// SignupAgePage is the age question's wording. Empty fields take the
// defaults (DefaultSignupAgePage). The minimum age is formatted into
// Message and Refused where they contain %d.
type SignupAgePage struct {
	// Title is the page heading.
	Title string
	// Message asks for the birth month and year.
	Message string
	// Refused is shown to a person under the minimum age.
	Refused string
}

// DefaultSignupAgePage is the wording used for empty SignupAgePage fields.
var DefaultSignupAgePage = SignupAgePage{
	Title:   "Before you create an account",
	Message: "Accounts are for adults, %d or older. Enter the month and year you were born.",
	Refused: "Sorry, you need to be %d or older to create an account. Nothing about you has been kept.",
}

func (p SignupAgePage) withDefaults() SignupAgePage {
	d := DefaultSignupAgePage
	for _, f := range []struct{ v, def *string }{
		{&p.Title, &d.Title}, {&p.Message, &d.Message}, {&p.Refused, &d.Refused},
	} {
		if *f.v == "" {
			*f.v = *f.def
		}
	}
	return p
}

// WithSignupAgePage sets the age question's wording. The question is asked
// only when SocialLoginConfig.SignupMinimumAge is set.
func WithSignupAgePage(page SignupAgePage) Option {
	return func(s *Server) { s.socialOpts.agePage = page }
}

// validateSignupMinimumAge reports whether n is acceptable as
// SocialLoginConfig.SignupMinimumAge.
func validateSignupMinimumAge(n int) error {
	if n < 0 || n > maxAgeAnswer {
		return fmt.Errorf("%w: signup_minimum_age must be from 0 to %d", ErrInvalidSocialLoginConfig, maxAgeAnswer)
	}
	return nil
}

// reachedAge reports whether a person born in the given month and year is
// at least minimum years old on now's date. Without the day it counts the
// last day of the birth month, so nobody younger is let through.
func reachedAge(year int, month time.Month, minimum int, now time.Time) bool {
	lastDay := time.Date(year, month+1, 0, 0, 0, 0, 0, time.UTC)
	birthday := time.Date(lastDay.Year()+minimum, lastDay.Month(), lastDay.Day(), 0, 0, 0, 0, time.UTC)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	return !today.Before(birthday)
}

// ageConfirmedKey marks a context whose upstream login answered the age
// question.
type ageConfirmedKey struct{}

func withAgeConfirmed(ctx context.Context) context.Context {
	return context.WithValue(ctx, ageConfirmedKey{}, true)
}

func ageConfirmed(ctx context.Context) bool {
	ok, _ := ctx.Value(ageConfirmedKey{}).(bool) //nolint:errcheck // a type assertion, not an error: absent means not confirmed
	return ok
}

// ageCheckedDirectory creates accounts only for logins that answered the
// age question, and otherwise behaves as the directory it wraps. It sits
// inside the sign-up gate, so an uninvited login is refused before it is
// asked its age.
type ageCheckedDirectory struct {
	PrincipalDirectory
}

// CreateFromExternal implements PrincipalDirectory.
func (d *ageCheckedDirectory) CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	if !ageConfirmed(ctx) {
		return nil, errSignupAgeRequired
	}
	return d.PrincipalDirectory.CreateFromExternal(ctx, login)
}

// EnsurePersonalOrg implements PersonalOrgEnsurer by delegating when the
// wrapped directory keeps personal organizations.
func (d *ageCheckedDirectory) EnsurePersonalOrg(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error {
	if e, ok := d.PrincipalDirectory.(PersonalOrgEnsurer); ok {
		return e.EnsurePersonalOrg(ctx, p, login)
	}
	return nil
}

// ageCookie returns the cookie name to use, dropping the __Host- prefix
// when the login runs over plain HTTP.
func (sl *socialLogin) ageCookie(name string) string {
	if sl.cookies.secure {
		return name
	}
	return strings.TrimPrefix(name, hostCookiePrefix)
}

func (sl *socialLogin) setAgeCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	http.SetCookie(w, sl.cookies.cookie(sl.ageCookie(name), value, int(ttl.Seconds())))
}

func (sl *socialLogin) clearAgeCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, sl.cookies.cookie(sl.ageCookie(name), "", -1))
}

// takeAgeConfirmation consumes the confirmation cookie of a login that
// answered the age question and returns ctx marked as confirmed when it
// belongs to provider. Any other outcome leaves ctx unmarked, so the login
// is asked again.
func (sl *socialLogin) takeAgeConfirmation(ctx context.Context, w http.ResponseWriter, r *http.Request, provider string) context.Context {
	token := cookieValue(r, sl.ageCookie(signupAgeConfirmedCookie))
	if token == "" {
		return ctx
	}
	sl.clearAgeCookie(w, signupAgeConfirmedCookie)
	data, err := sl.states.Take(ctx, token)
	if err != nil {
		if !errors.Is(err, oauthclient.ErrInvalidState) {
			LoggerFromContext(ctx).Error("reading sign-up age confirmation", "error", err)
		}
		return ctx
	}
	if data.Nonce != signupAgeConfirmed || data.Provider != provider {
		return ctx
	}
	return withAgeConfirmed(ctx)
}

// askAge parks the provider and destination of a login that needs the age
// question and sends the browser to it. Nothing the provider said about the
// person is kept.
func (sl *socialLogin) askAge(w http.ResponseWriter, r *http.Request, provider, target string) {
	ctx := r.Context()
	token, err := newSessionToken()
	if err == nil {
		err = sl.states.Put(ctx, token, oauthclient.StateData{
			Provider:    provider,
			RedirectURL: target,
			Nonce:       signupAgePending,
		}, signupAgePendingTTL)
	}
	if err != nil {
		LoggerFromContext(ctx).Error("starting the sign-up age question", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sl.setAgeCookie(w, signupAgePendingCookie, token, signupAgePendingTTL)
	http.Redirect(w, r, SignupAgePath, http.StatusSeeOther)
}

var signupAgeTemplate = template.Must(template.New("signup-age").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Page.Title}}</title></head>
<body><main><h1>{{.Page.Title}}</h1>
{{if .Refused}}<p role="status">{{.RefusedText}}</p>{{else if .Expired}}<p role="status">This page has expired. <a href="{{.LoginPath}}">Sign in again</a>.</p>{{else}}
<p>{{.MessageText}}</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<label for="month">Month</label>
<select id="month" name="month" required><option value="" selected></option>{{range .Months}}<option value="{{.Value}}">{{.Name}}</option>{{end}}</select>
<label for="year">Year</label>
<select id="year" name="year" required><option value="" selected></option>{{range .Years}}<option value="{{.}}">{{.}}</option>{{end}}</select>
<button type="submit">Continue</button>
</form>{{end}}
</main></body></html>
`))

type monthOption struct {
	Value int
	Name  string
}

type signupAgeView struct {
	Page        SignupAgePage
	Action      string
	LoginPath   string
	MessageText string
	RefusedText string
	Months      []monthOption
	Years       []int
	Refused     bool
	Expired     bool
	Error       string
}

func (sl *socialLogin) renderAge(w http.ResponseWriter, r *http.Request, status int, v signupAgeView) {
	minimum := sl.cfg.SignupMinimumAge
	v.Page, v.Action, v.LoginPath = sl.agePage, SignupAgePath, LoginPath
	v.MessageText = formatAge(sl.agePage.Message, minimum)
	v.RefusedText = formatAge(sl.agePage.Refused, minimum)
	for m := time.January; m <= time.December; m++ {
		v.Months = append(v.Months, monthOption{Value: int(m), Name: m.String()})
	}
	// Years run newest first and include years that are too recent, so the
	// list does not hint at the answer that is needed.
	this := sl.now().Year()
	for y := this; y >= this-maxAgeAnswer; y-- {
		v.Years = append(v.Years, y)
	}
	// The answer restarts the upstream login: the submission may redirect
	// through the provider and back to wherever the sign-in returns, which
	// is not known here, so form-action allows any https target (and http
	// when the issuer itself is http, in development).
	targets := []string{"https:"}
	if strings.HasPrefix(sl.redirects.issuerOrigin, "http://") {
		targets = append(targets, "http:")
	}
	allowFormTargets(w, targets)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := signupAgeTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering sign-up age page", "error", err)
	}
}

// formatAge puts the minimum age into wording that asks for it.
func formatAge(text string, minimum int) string {
	return strings.Replace(text, "%d", strconv.Itoa(minimum), 1)
}

// handleAgePage serves GET SignupAgePath.
func (sl *socialLogin) handleAgePage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	switch {
	case cookieValue(r, sl.ageCookie(signupAgeRefusedCookie)) != "":
		sl.renderAge(w, r, http.StatusForbidden, signupAgeView{Refused: true})
	case cookieValue(r, sl.ageCookie(signupAgePendingCookie)) == "":
		sl.renderAge(w, r, http.StatusBadRequest, signupAgeView{Expired: true})
	default:
		sl.renderAge(w, r, http.StatusOK, signupAgeView{})
	}
}

// handleAgeAnswer serves POST SignupAgePath. An answer under the minimum
// age discards the pending login and marks the browser so the question is
// not asked again at once; an answer at or over it restarts the upstream
// login, which then creates the account.
func (sl *socialLogin) handleAgeAnswer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)
	if !sl.redirects.fromTrustedOrigin(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	if cookieValue(r, sl.ageCookie(signupAgeRefusedCookie)) != "" {
		sl.renderAge(w, r, http.StatusForbidden, signupAgeView{Refused: true})
		return
	}
	pending := cookieValue(r, sl.ageCookie(signupAgePendingCookie))
	if pending == "" {
		sl.renderAge(w, r, http.StatusBadRequest, signupAgeView{Expired: true})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	this := sl.now().Year()
	month, mErr := strconv.Atoi(r.PostForm.Get("month"))
	year, yErr := strconv.Atoi(r.PostForm.Get("year"))
	if mErr != nil || yErr != nil || month < 1 || month > 12 || year > this || year < this-maxAgeAnswer {
		sl.renderAge(w, r, http.StatusBadRequest, signupAgeView{Error: "Choose the month and year you were born."})
		return
	}

	sl.clearAgeCookie(w, signupAgePendingCookie)
	data, err := sl.states.Take(ctx, pending)
	if err != nil || data.Nonce != signupAgePending {
		if err != nil && !errors.Is(err, oauthclient.ErrInvalidState) {
			logger.Error("reading pending sign-up age question", "error", err)
		}
		sl.renderAge(w, r, http.StatusBadRequest, signupAgeView{Expired: true})
		return
	}

	if !reachedAge(year, time.Month(month), sl.cfg.SignupMinimumAge, sl.now()) {
		logger.Info("sign-up refused: under the minimum age", "provider", data.Provider)
		sl.setAgeCookie(w, signupAgeRefusedCookie, "1", signupAgeRefusedTTL)
		sl.renderAge(w, r, http.StatusForbidden, signupAgeView{Refused: true})
		return
	}

	token, err := newSessionToken()
	if err == nil {
		err = sl.states.Put(ctx, token, oauthclient.StateData{
			Provider:    data.Provider,
			RedirectURL: data.RedirectURL,
			Nonce:       signupAgeConfirmed,
		}, signupAgeConfirmedTTL)
	}
	if err != nil {
		logger.Error("confirming sign-up age", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sl.setAgeCookie(w, signupAgeConfirmedCookie, token, signupAgeConfirmedTTL)
	logger.Info("sign-up age confirmed", "provider", data.Provider)
	http.Redirect(w, r, startURL(data.Provider, data.RedirectURL), http.StatusSeeOther)
}
