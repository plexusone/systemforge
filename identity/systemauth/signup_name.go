package systemauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// The sign-up name step (ADR-024). A name is shown to other people, so it is
// never made from the person's email address: when an account is about to be
// created for a login that gave no name, SystemAuth asks for one, and for the
// name of the person's personal organization, before creating it.
const (
	// SignupNamePath shows the name form (GET) and takes the answer (POST).
	SignupNamePath = "/signup/name"

	// signupNameCookie binds a parked sign-up to its browser.
	signupNameCookie = "__Host-sf_signup_name"

	// signupNameTTL is how long a sign-up waits for its name.
	signupNameTTL = 15 * time.Minute

	// Longest names accepted, in characters.
	maxPersonNameLength = 100
	maxOrgNameLength    = 80
)

// errSignupNameRequired is returned by the name-checked directory when an
// account would be created for a login with no name. The error also carries
// the login, so the sign-up can be parked.
var errSignupNameRequired = errors.New("systemauth: sign-up needs the person's name")

// nameRequiredError is errSignupNameRequired with the login that needs it.
type nameRequiredError struct{ login ExternalLogin }

func (*nameRequiredError) Error() string { return errSignupNameRequired.Error() }

// Is makes the error match errSignupNameRequired.
func (*nameRequiredError) Is(target error) bool { return target == errSignupNameRequired }

// nameCheckedDirectory creates accounts only for logins that have a name, and
// otherwise behaves as the directory it wraps. It sits inside the sign-up
// gate and the age check, so an uninvited or underage login is refused before
// it is asked for a name.
type nameCheckedDirectory struct {
	PrincipalDirectory
}

// CreateFromExternal implements PrincipalDirectory.
func (d *nameCheckedDirectory) CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	if strings.TrimSpace(login.Name) == "" {
		return nil, &nameRequiredError{login: login}
	}
	return d.PrincipalDirectory.CreateFromExternal(ctx, login)
}

// EnsurePersonalOrg implements PersonalOrgEnsurer by delegating when the
// wrapped directory keeps personal organizations.
func (d *nameCheckedDirectory) EnsurePersonalOrg(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error {
	if e, ok := d.PrincipalDirectory.(PersonalOrgEnsurer); ok {
		return e.EnsurePersonalOrg(ctx, p, login)
	}
	return nil
}

// cleanName returns a name as it is stored: trimmed, with runs of spaces made
// one, and ok only when it is between 1 and max characters, printable, and
// not an email address (no "@"), which a name field is not for.
func cleanName(input string, limit int) (string, bool) {
	name := strings.Join(strings.Fields(input), " ")
	if name == "" || utf8.RuneCountInString(name) > limit || strings.Contains(name, "@") {
		return "", false
	}
	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", false
		}
	}
	return name, true
}

func (sl *socialLogin) signupNameCookieName() string { return sl.ageCookie(signupNameCookie) }

// signupNameBinding is the token binding of a parked sign-up: a hash of its
// browser cookie.
func signupNameBinding(cookie string) string { return "name:" + hashSessionToken(cookie) }

// signupNameCSRF derives the name form's token from the parked sign-up's
// cookie, which a cross-site page cannot read.
func signupNameCSRF(cookie string) string {
	mac := hmac.New(sha256.New, []byte(cookie))
	mac.Write([]byte("systemauth-signup-name-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var signupNameTemplate = template.Must(template.New("signup-name").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` + pageStyleLink + `
<title>{{.Title}}</title></head>
<body><main><h1>{{.Title}}</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
{{if .Form}}<p>Tell us what to call you. Your name is shown to other people you work with and in the apps you sign in to; we do not take it from your email address.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label for="name">Your name</label>
<input id="name" name="name" type="text" autocomplete="name" maxlength="{{.MaxName}}" value="{{.Name}}" required autofocus>
<label for="organization_name">Name for your personal workspace (optional)</label>
<input id="organization_name" name="organization_name" type="text" maxlength="{{.MaxOrg}}" value="{{.OrgName}}">
<button type="submit">Continue</button>
</form>{{end}}
{{if .Restart}}<p><a href="{{.LoginPath}}">Sign in again</a></p>{{end}}
</main></body></html>
`))

type signupNameView struct {
	Title, Error, CSRF, Name, OrgName string
	Action, LoginPath                 string
	MaxName, MaxOrg                   int
	Form, Restart                     bool
	status                            int
}

func (sl *socialLogin) renderSignupName(w http.ResponseWriter, r *http.Request, v signupNameView) {
	noStore(w)
	if v.Title == "" {
		v.Title = "What should we call you?"
	}
	v.Action, v.LoginPath, v.MaxName, v.MaxOrg = SignupNamePath, LoginPath, maxPersonNameLength, maxOrgNameLength
	if v.Form {
		// Answering completes the sign-in, which redirects to wherever it
		// returns (possibly through /oauth/authorize to a client), so
		// form-action allows any https target (and http in development).
		targets := []string{"https:"}
		if strings.HasPrefix(sl.redirects.issuerOrigin, "http://") {
			targets = append(targets, "http:")
		}
		allowFormTargets(w, targets)
	}
	if v.status == 0 {
		v.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(v.status)
	if err := signupNameTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering the name page", "error", err)
	}
}

func expiredSignupNameView() signupNameView {
	return signupNameView{
		Title:   "Sign in again",
		Restart: true,
		Error:   "This sign-up has expired or was completed. Sign in again to continue.",
		status:  http.StatusBadRequest,
	}
}

// askName parks a proven login that needs a name, bound to this browser, and
// sends the browser to the name form. Nothing is created until it is answered.
func (sl *socialLogin) askName(ctx context.Context, w http.ResponseWriter, r *http.Request, login ExternalLogin, redirectURL string) {
	logger := LoggerFromContext(ctx)
	cookie, err := newSessionToken()
	var data []byte
	if err == nil {
		data, err = json.Marshal(pendingFromLogin(login, redirectURL, ageConfirmed(ctx)))
	}
	var token string
	if err == nil {
		token, err = newSessionToken()
	}
	if err == nil {
		now := sl.now()
		err = sl.verifyTokens.Create(ctx, token, VerificationToken{
			Purpose:   PurposeSignUpName,
			Email:     login.Email,
			Binding:   signupNameBinding(cookie),
			Data:      data,
			CreatedAt: now,
			ExpiresAt: now.Add(signupNameTTL),
		})
	}
	if err != nil {
		logger.Error("parking a sign-up for its name", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, sl.cookies.cookie(sl.signupNameCookieName(), cookie, int(signupNameTTL.Seconds())))
	http.Redirect(w, r, SignupNamePath, http.StatusSeeOther)
}

// pendingSignUp returns the browser's parked sign-up cookie and its token, or
// ok false when it answered the request.
func (sl *socialLogin) pendingSignUp(w http.ResponseWriter, r *http.Request) (string, *VerificationToken, bool) {
	cookie := cookieValue(r, sl.signupNameCookieName())
	if cookie == "" {
		sl.renderSignupName(w, r, expiredSignupNameView())
		return "", nil, false
	}
	t, err := sl.verifyTokens.Latest(r.Context(), PurposeSignUpName, signupNameBinding(cookie))
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenNotFound) {
			LoggerFromContext(r.Context()).Error("reading a parked sign-up", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return "", nil, false
		}
		sl.renderSignupName(w, r, expiredSignupNameView())
		return "", nil, false
	}
	return cookie, t, true
}

// handleSignupNamePage serves GET /signup/name.
func (sl *socialLogin) handleSignupNamePage(w http.ResponseWriter, r *http.Request) {
	if !sl.limit(w, r, "signup_name_page", DefaultSocialLoginLimit) {
		return
	}
	cookie, _, ok := sl.pendingSignUp(w, r)
	if !ok {
		return
	}
	sl.renderSignupName(w, r, signupNameView{Form: true, CSRF: signupNameCSRF(cookie)})
}

// handleSignupNameSubmit serves POST /signup/name: it checks the names, uses
// the parked sign-up once, and creates the account with them.
func (sl *socialLogin) handleSignupNameSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	if !sl.limit(w, r, "signup_name_submit", DefaultSocialLoginLimit) {
		return
	}
	cookie := sl.checkPendingForm(w, r, sl.signupNameCookieName(), signupNameCSRF, func() {
		sl.renderSignupName(w, r, expiredSignupNameView())
	})
	if cookie == "" {
		return
	}
	_, t, ok := sl.pendingSignUp(w, r)
	if !ok {
		return
	}
	rawName, rawOrg := r.PostForm.Get("name"), r.PostForm.Get("organization_name")
	name, nameOK := cleanName(rawName, maxPersonNameLength)
	org, orgOK := "", true
	if strings.TrimSpace(rawOrg) != "" {
		org, orgOK = cleanName(rawOrg, maxOrgNameLength)
	}
	if !nameOK || !orgOK {
		msg := "Enter your name, up to 100 characters. An email address is not a name."
		if nameOK {
			msg = "Enter a workspace name of up to 80 characters, or leave it empty. An email address is not a name."
		}
		sl.renderSignupName(w, r, signupNameView{
			Form: true, CSRF: signupNameCSRF(cookie), Error: msg,
			Name: strings.TrimSpace(rawName), OrgName: strings.TrimSpace(rawOrg), status: http.StatusBadRequest,
		})
		return
	}
	var pending pendingSignIn
	if err := json.Unmarshal(t.Data, &pending); err != nil {
		logger.Error("reading a parked sign-up", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The parked sign-up is used once: of concurrent answers, one wins.
	if err := sl.verifyTokens.ConsumeToken(ctx, t.ID, PurposeSignUpName, signupNameBinding(cookie)); err != nil {
		if !errors.Is(err, ErrVerificationTokenInvalid) {
			logger.Error("using a parked sign-up", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sl.renderSignupName(w, r, expiredSignupNameView())
		return
	}
	http.SetCookie(w, sl.cookies.cookie(sl.signupNameCookieName(), "", -1))

	login := pending.login()
	login.Name, login.OrganizationName = name, org
	if pending.AgeConfirmed {
		ctx = withAgeConfirmed(ctx)
	}
	ctx = sl.withSignupCode(ctx, r)
	p, err := ResolveExternalLogin(ctx, sl.directory, login, sl.now())
	sl.completeSignIn(ctx, w, r, login.Provider, pending.RedirectURL, p, err)
}
