package systemauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/plexusone/omnimail"
)

// Email sign-in routes (ADR-023), mounted with social login when
// social_login.email is configured. A person enters an address, SystemAuth
// mails a one-time code, and the person types it in the browser that asked.
const (
	// EmailLoginPath shows the address form (GET) and sends the code (POST).
	EmailLoginPath = "/login/email"
	// EmailCodePath shows the code form (GET) and checks the code (POST).
	EmailCodePath = "/login/email/code"
	// EmailCodeResendPath sends a new code (POST).
	EmailCodeResendPath = "/login/email/code/resend"

	// emailCodeCookie binds a pending email sign-in to its browser.
	emailCodeCookie = "__Host-sf_email_code"

	// emailLoginProvider names email sign-in as an external identity
	// provider: the identity is (email, the normalized address).
	emailLoginProvider = "email"

	// maxEmailLength is the longest address accepted (RFC 5321).
	maxEmailLength = 254
)

// emailLogin is the state of email sign-in.
type emailLogin struct {
	digits      int
	ttl         time.Duration
	maxAttempts int
	// key keys the hash of codes; see emailCodeKey.
	key []byte
}

// emailCodePayload is kept in the sign-in code token's Data. It holds a
// keyed hash of the code, never the code.
type emailCodePayload struct {
	MAC         string `json:"mac"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

// emailCodeKey derives the key of code hashes from the token HMAC secret,
// so the two uses of the secret stay separate. A code has only a million
// possible values at the shortest length, so it is stored under a keyed hash:
// an unkeyed hash would reverse from a copy of the database.
func emailCodeKey(secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("systemauth/email-code/v1"))
	return mac.Sum(nil)
}

// emailCodeMAC is the stored form of code: bound to the browser's binding
// and the address, so a copied value is useless for any other sign-in.
func emailCodeMAC(key []byte, binding, email, code string) string {
	mac := hmac.New(sha256.New, key)
	for _, part := range []string{binding, email, code} {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// newEmailCode returns a uniformly random code of digits decimal digits.
// rand.Int draws from the full range without modulo bias.
func newEmailCode(digits int) (string, error) {
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits)), nil)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", digits, n), nil
}

// cleanEmailCode removes the spaces and hyphens people type into a code and
// reports whether what is left is exactly digits decimal digits.
func cleanEmailCode(input string, digits int) (string, bool) {
	var b strings.Builder
	for _, r := range input {
		switch {
		case r == ' ' || r == '-':
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			return "", false
		}
	}
	return b.String(), b.Len() == digits
}

// normalizeLoginEmail returns the address in the form it is stored and
// mailed to: only the address, lower case. Plus-addressing is kept, since
// stripping it would merge mailboxes some providers keep apart.
func normalizeLoginEmail(input string) (string, bool) {
	input = strings.TrimSpace(input)
	if input == "" || len(input) > maxEmailLength {
		return "", false
	}
	addr, err := omnimail.ParseAddress(input)
	if err != nil || addr.Email == "" || len(addr.Email) > maxEmailLength {
		return "", false
	}
	return strings.ToLower(addr.Email), true
}

func (sl *socialLogin) emailCodeCookieName() string { return sl.ageCookie(emailCodeCookie) }

// emailCodeBinding is the token binding of a pending email sign-in: a hash
// of its browser cookie, so the stored row cannot be turned back into it.
func emailCodeBinding(cookie string) string { return "code:" + hashSessionToken(cookie) }

// emailCodeCSRF derives the code forms' token from the pending sign-in's
// cookie, which a cross-site page cannot read.
func emailCodeCSRF(cookie string) string {
	mac := hmac.New(sha256.New, []byte(cookie))
	mac.Write([]byte("systemauth-email-code-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var emailLoginTemplate = template.Must(template.New("email-login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` + pageStyleLink + `
<title>{{.Title}}</title></head>
<body><main><h1>{{.Title}}</h1>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
{{if .Form}}<p>Enter your email address and we will send you a code to sign in.</p>
<form method="post" action="{{.Action}}">
<label for="email">Email address</label>
<input id="email" name="email" type="email" inputmode="email" autocomplete="email" maxlength="254" required autofocus>
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
<button type="submit">Send code</button>
</form>{{end}}
{{if .Restart}}<p><a href="{{.LoginPath}}">Sign in again</a></p>{{end}}
</main></body></html>
`))

var emailCodeTemplate = template.Must(template.New("email-code").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` + pageStyleLink + `
<title>{{.Title}}</title></head>
<body><main><h1>{{.Title}}</h1>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
{{if .Email}}<p>If we could, we sent a {{.Digits}}-digit code to <strong>{{.Email}}</strong>. Enter it here, in this browser. It works once and expires in {{.ExpiresIn}}.</p>
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label for="code">Code</label>
<input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="{{.MaxInput}}" required autofocus>
<button type="submit">Sign in</button>
</form>
<form method="post" action="{{.ResendAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit">Send a new code</button>
</form>{{end}}
{{if .Restart}}<p><a href="{{.RestartURL}}">Sign in again</a></p>{{end}}
</main></body></html>
`))

type emailLoginView struct {
	Title, Error, ReturnTo string
	Action, LoginPath      string
	Form, Restart          bool
	status                 int
}

type emailCodeView struct {
	Title, Message, Error           string
	Email, ExpiresIn, CSRF          string
	Action, ResendAction, LoginPath string
	Digits, MaxInput                int
	Restart                         bool
	// RestartURL is where "Sign in again" leads: the sign-in page, with the
	// pending sign-in's destination when it is known.
	RestartURL           string
	status               int
	formTargetsAnyOrigin bool
}

func (sl *socialLogin) renderEmailLogin(w http.ResponseWriter, r *http.Request, v emailLoginView) {
	noStore(w)
	if v.Title == "" {
		v.Title = "Sign in with email"
	}
	v.Action, v.LoginPath = EmailLoginPath, LoginPath
	if v.status == 0 {
		v.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(v.status)
	if err := emailLoginTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering email sign-in page", "error", err)
	}
}

func (sl *socialLogin) renderEmailCode(w http.ResponseWriter, r *http.Request, v emailCodeView) {
	noStore(w)
	if v.Title == "" {
		v.Title = "Enter your code"
	}
	v.Action, v.ResendAction, v.LoginPath = EmailCodePath, EmailCodeResendPath, LoginPath
	if v.RestartURL == "" {
		v.RestartURL = LoginPath
	}
	v.Digits = sl.email.digits
	v.MaxInput = sl.email.digits * 2 // room for the spaces and hyphens people type
	if v.formTargetsAnyOrigin {
		// A correct code completes the sign-in, which redirects to wherever
		// it returns (possibly through /oauth/authorize to a client), so
		// form-action allows any https target (and http when the issuer is
		// http, in development).
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
	if err := emailCodeTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering email code page", "error", err)
	}
}

// expiredEmailCodeView is shown when the browser has no usable pending
// sign-in. returnTo, when known, is carried to the sign-in page so signing
// in again resumes where the person was going.
func expiredEmailCodeView(returnTo string) emailCodeView {
	v := emailCodeView{
		Title:   "Sign in again",
		Message: "This sign-in has expired, was completed or has used up its tries. Sign in again to get a new code.",
		Restart: true,
		status:  http.StatusBadRequest,
	}
	if returnTo != "" {
		v.RestartURL = LoginPath + "?return_to=" + url.QueryEscape(returnTo)
	}
	return v
}

// handleEmailLoginPage serves GET /login/email: the address form.
func (sl *socialLogin) handleEmailLoginPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !sl.limit(w, r, "email_login_page", DefaultSocialLoginLimit) {
		return
	}
	target, err := sl.redirects.resolve(r.URL.Query().Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	if err := sl.keepInviteCode(w, r); err != nil {
		LoggerFromContext(r.Context()).Error("keeping invite code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sl.renderEmailLogin(w, r, emailLoginView{Form: true, ReturnTo: target})
}

// issueEmailCode stores a new sign-in code for the pending sign-in bound to
// cookie and mails it when decision allows. When the send limits suppress the
// message, what is stored is a decoy that no entry can match: the response is
// the same, and the limits on mail also bound how many live codes can exist
// for an address, so they bound the guesses made at it. Without the decoy, a
// suppressed request would still make a live code, one nobody holds but a
// guesser could hit, and the mail limits would not cap the guessing.
func (sl *socialLogin) issueEmailCode(ctx context.Context, cookie, email, redirectURL string, decision sendDecision) error {
	binding := emailCodeBinding(cookie)
	code, err := newEmailCode(sl.email.digits)
	if err != nil {
		return err
	}
	stored := code
	if decision != sendAllowed {
		// Not digits, so no entry the form accepts can match it, and 128
		// random bits, so no entry of any shape can.
		raw := make([]byte, 16)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		stored = "decoy:" + base64.RawURLEncoding.EncodeToString(raw)
	}
	data, err := json.Marshal(emailCodePayload{
		MAC:         emailCodeMAC(sl.email.key, binding, email, stored),
		RedirectURL: redirectURL,
	})
	if err != nil {
		return err
	}
	token, err := newSessionToken()
	if err != nil {
		return err
	}
	now := sl.now()
	if err := sl.verifyTokens.Create(ctx, token, VerificationToken{
		Purpose:   PurposeSignInCode,
		Email:     email,
		Binding:   binding,
		Data:      data,
		CreatedAt: now,
		ExpiresAt: now.Add(sl.email.ttl),
	}); err != nil {
		return err
	}
	if decision == sendAllowed {
		if err := sl.mail.send(ctx, mailSignInCode, email, mailData{Code: code, ExpiresIn: humanDuration(sl.email.ttl)}); err != nil {
			// Logged, not shown: the person sees the same page and can ask
			// for another code.
			LoggerFromContext(ctx).Error("sending sign-in code mail", "error", err)
		}
	}
	return nil
}

// handleEmailLoginRequest serves POST /login/email: it mails a code to the
// address and sends the browser to the code page. The answer does not
// depend on whether the address has an account, and no account is looked up.
func (sl *socialLogin) handleEmailLoginRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)
	if !sl.limit(w, r, "email_login_request", DefaultSocialLoginLimit) {
		return
	}
	if !sl.redirects.fromIssuer(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	target, err := sl.redirects.resolve(r.PostForm.Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	email, ok := normalizeLoginEmail(r.PostForm.Get("email"))
	if !ok {
		sl.renderEmailLogin(w, r, emailLoginView{
			Form: true, ReturnTo: target, Error: "Enter a valid email address.", status: http.StatusBadRequest,
		})
		return
	}
	decision := sl.mail.allowSend(w, r, email)
	if decision == sendRefused || decision == sendFailed {
		return
	}
	old := cookieValue(r, sl.emailCodeCookieName())
	if decision == sendSuppressed && old != "" {
		// Nothing can be sent. A browser that already holds a pending
		// sign-in for this address keeps it, so a code that arrives late
		// still works; the answer is the same as for a sent message.
		if t, err := sl.verifyTokens.Latest(ctx, PurposeSignInCode, emailCodeBinding(old)); err == nil && t.Email == email {
			http.Redirect(w, r, EmailCodePath, http.StatusSeeOther)
			return
		}
	}
	cookie, err := newSessionToken()
	if err == nil {
		err = sl.issueEmailCode(ctx, cookie, email, target, decision)
	}
	if err != nil {
		logger.Error("starting email sign-in", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The new request replaces the browser's earlier pending sign-in. It is
	// retired after the new code is stored, so a failure to store leaves the
	// earlier one usable.
	if old != "" {
		if _, err := sl.verifyTokens.Revoke(ctx, PurposeSignInCode, emailCodeBinding(old)); err != nil {
			logger.Warn("revoking the earlier sign-in code", "error", err)
		}
	}
	http.SetCookie(w, sl.cookies.cookie(sl.emailCodeCookieName(), cookie, int(sl.email.ttl.Seconds())))
	http.Redirect(w, r, EmailCodePath, http.StatusSeeOther)
}

// pendingEmailCode returns the browser's pending-sign-in cookie and its
// newest usable code token, or ok false when it answered the request.
func (sl *socialLogin) pendingEmailCode(w http.ResponseWriter, r *http.Request) (string, *VerificationToken, bool) {
	cookie := cookieValue(r, sl.emailCodeCookieName())
	if cookie == "" {
		sl.renderEmailCode(w, r, expiredEmailCodeView(""))
		return "", nil, false
	}
	t, err := sl.verifyTokens.Latest(r.Context(), PurposeSignInCode, emailCodeBinding(cookie))
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenNotFound) {
			LoggerFromContext(r.Context()).Error("reading pending email sign-in", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return "", nil, false
		}
		sl.renderEmailCode(w, r, expiredEmailCodeView(""))
		return "", nil, false
	}
	return cookie, t, true
}

// handleEmailCodePage serves GET /login/email/code.
func (sl *socialLogin) handleEmailCodePage(w http.ResponseWriter, r *http.Request) {
	cookie, t, ok := sl.pendingEmailCode(w, r)
	if !ok {
		return
	}
	v := emailCodeView{Email: t.Email, ExpiresIn: humanDuration(sl.email.ttl), CSRF: emailCodeCSRF(cookie), formTargetsAnyOrigin: true}
	if r.URL.Query().Get("resent") != "" {
		v.Message = "If we could, we sent another code. Use the newest one you received."
	}
	sl.renderEmailCode(w, r, v)
}

// checkEmailCodeForm checks a code-page form (see checkPendingForm). It
// returns the cookie, or "" when it answered the request.
func (sl *socialLogin) checkEmailCodeForm(w http.ResponseWriter, r *http.Request) string {
	return sl.checkPendingForm(w, r, sl.emailCodeCookieName(), emailCodeCSRF, func() {
		sl.renderEmailCode(w, r, expiredEmailCodeView(""))
	})
}

// handleEmailCodeSubmit serves POST /login/email/code. Each entry is counted
// against the code before it is compared, in one atomic step, so the limit
// holds however many entries arrive together. A correct code is used once,
// and only together with the cookie of the browser that asked for it.
func (sl *socialLogin) handleEmailCodeSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	if !sl.limit(w, r, "email_code_submit", DefaultSocialLoginLimit) {
		return
	}
	cookie := sl.checkEmailCodeForm(w, r)
	if cookie == "" {
		return
	}
	binding := emailCodeBinding(cookie)
	t, err := sl.verifyTokens.RecordAttempt(ctx, PurposeSignInCode, binding, sl.email.maxAttempts)
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenInvalid) {
			logger.Error("counting a sign-in code attempt", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sl.signInRefused(ctx, emailLoginProvider, "", "code_unusable")
		sl.renderEmailCode(w, r, expiredEmailCodeView(""))
		return
	}
	var payload emailCodePayload
	if err := json.Unmarshal(t.Data, &payload); err != nil {
		logger.Error("reading pending email sign-in", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// An entry of the wrong shape is hashed as typed, so the work does not
	// show whether it had the right shape.
	entered, shaped := cleanEmailCode(r.PostForm.Get("code"), sl.email.digits)
	if !shaped {
		entered = r.PostForm.Get("code")
	}
	got := emailCodeMAC(sl.email.key, binding, t.Email, entered)
	if !shaped || !hmac.Equal([]byte(got), []byte(payload.MAC)) {
		sl.signInRefused(ctx, emailLoginProvider, "", "code_mismatch")
		left := sl.email.maxAttempts - t.Attempts
		if left <= 0 {
			// Nothing to revoke: RecordAttempt refuses further entries, and
			// revoking here could consume a replacement issued meanwhile.
			sl.renderEmailCode(w, r, expiredEmailCodeView(payload.RedirectURL))
			return
		}
		sl.renderEmailCode(w, r, emailCodeView{
			Email: t.Email, ExpiresIn: humanDuration(sl.email.ttl), CSRF: emailCodeCSRF(cookie),
			Error:  fmt.Sprintf("That code is not right. You have %d %s left.", left, plural(left, "try", "tries")),
			status: http.StatusBadRequest, formTargetsAnyOrigin: true,
		})
		return
	}

	// The code is right. Using the row it matched is the single use: of
	// concurrent correct entries one update matches the row and the others
	// find it used, and a code that was replaced since is refused without
	// touching its replacement.
	if err := sl.verifyTokens.ConsumeToken(ctx, t.ID, PurposeSignInCode, binding); err != nil {
		if !errors.Is(err, ErrVerificationTokenInvalid) {
			logger.Error("using a sign-in code", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sl.signInRefused(ctx, emailLoginProvider, "", "code_unusable")
		sl.renderEmailCode(w, r, expiredEmailCodeView(payload.RedirectURL))
		return
	}
	// Any other pending code of this browser is dead now.
	if _, err := sl.verifyTokens.Revoke(ctx, PurposeSignInCode, binding); err != nil {
		logger.Warn("revoking the browser's other sign-in codes", "error", err)
	}
	http.SetCookie(w, sl.cookies.cookie(sl.emailCodeCookieName(), "", -1))
	sl.completeEmailSignIn(ctx, w, r, t.Email, payload.RedirectURL)
}

// completeEmailSignIn finishes a sign-in whose address was proven by a code:
// the identity is resolved as any provider's, with the address counted as
// proven, so the sign-up gate, linking by verified email, consent and the
// session follow the same path as social login.
func (sl *socialLogin) completeEmailSignIn(ctx context.Context, w http.ResponseWriter, r *http.Request, email, redirectURL string) {
	if sl.cfg.SignupMinimumAge > 0 {
		ctx = sl.takeAgeConfirmation(ctx, w, r, emailLoginProvider)
	}
	ctx = sl.withSignupCode(ctx, r)
	login := ExternalLogin{
		Provider:    emailLoginProvider,
		Subject:     email,
		Email:       email,
		EmailProven: true,
	}
	p, err := ResolveExternalLogin(ctx, sl.directory, login, sl.now())
	if err == nil && !strings.EqualFold(p.Email, email) {
		// The identity is linked to this address but the account has since
		// moved to another one: the old mailbox no longer reaches it.
		sl.signInRefused(ctx, emailLoginProvider, "", "stale_email_identity")
		LoggerFromContext(ctx).Info("email sign-in refused: the account no longer uses this address", "principal_id", p.ID)
		http.Error(w, "this address is no longer used by the account", http.StatusForbidden)
		return
	}
	sl.completeSignIn(ctx, w, r, emailLoginProvider, redirectURL, p, err)
}

// handleEmailCodeResend serves POST /login/email/code/resend: it replaces the
// pending code with a new one, within the send limits, answering the same way
// whether or not it was sent.
func (sl *socialLogin) handleEmailCodeResend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	if !sl.limit(w, r, "email_code_resend", DefaultSocialLoginLimit) {
		return
	}
	if sl.checkEmailCodeForm(w, r) == "" {
		return
	}
	cookie, t, ok := sl.pendingEmailCode(w, r)
	if !ok {
		return
	}
	var payload emailCodePayload
	if err := json.Unmarshal(t.Data, &payload); err != nil {
		logger.Error("reading pending email sign-in", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	decision := sl.mail.allowSend(w, r, t.Email)
	if decision == sendRefused || decision == sendFailed {
		return
	}
	if decision == sendSuppressed {
		// Nothing can be sent, so nothing changes: the code already mailed
		// stays usable, and the answer is the same as for a sent message.
		http.Redirect(w, r, EmailCodePath+"?resent=1", http.StatusSeeOther)
		return
	}
	// The replacement is stored first and the earlier code retired after,
	// so a failure to store leaves the earlier one usable. Entries are
	// counted against the newest code only, so the earlier one is already
	// out of use once the replacement exists.
	if err := sl.issueEmailCode(ctx, cookie, t.Email, payload.RedirectURL, decision); err != nil {
		logger.Error("resending a sign-in code", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := sl.verifyTokens.ConsumeToken(ctx, t.ID, PurposeSignInCode, emailCodeBinding(cookie)); err != nil && !errors.Is(err, ErrVerificationTokenInvalid) {
		logger.Warn("retiring the replaced sign-in code", "error", err)
	}
	http.SetCookie(w, sl.cookies.cookie(sl.emailCodeCookieName(), cookie, int(sl.email.ttl.Seconds())))
	http.Redirect(w, r, EmailCodePath+"?resent=1", http.StatusSeeOther)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
