package systemauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"github.com/plexusone/omnimail"

	"github.com/plexusone/systemforge/contract/audit"
)

// Verify-email routes, mounted with social login when mail is configured
// (ADR-003). A sign-in whose provider email is unverified is held as
// pending, bound to the browser that started it, while SystemAuth mails a
// link to the address.
const (
	// VerifyEmailPath shows the pending sign-in's "check your email" page.
	VerifyEmailPath = "/login/verify-email"
	// VerifyEmailResendPath sends a new link (POST).
	VerifyEmailResendPath = "/login/verify-email/resend"
	// VerifyEmailConfirmPath is the mailed link: GET shows a confirmation
	// form, POST uses the token and completes the sign-in.
	VerifyEmailConfirmPath = "/login/verify-email/confirm"

	// verifyEmailCookie binds a pending sign-in to its browser.
	verifyEmailCookie = "__Host-sf_verify_email"
)

// Security event types of email verification.
const (
	// EventEmailVerificationSent records a verification link issued for a
	// pending sign-in or an email change.
	EventEmailVerificationSent = "systemauth.email_verification.sent"
	// EventEmailVerified records an address proven by a verification link.
	EventEmailVerified = "systemauth.email.verified"
)

// pendingSignIn is a sign-in held until its email is verified. It is kept
// in the verification token's Data, never in the browser.
type pendingSignIn struct {
	Provider     string `json:"provider"`
	Subject      string `json:"subject"`
	Email        string `json:"email"`
	Name         string `json:"name,omitempty"`
	Username     string `json:"username,omitempty"`
	AvatarURL    string `json:"avatar_url,omitempty"`
	RedirectURL  string `json:"redirect_url,omitempty"`
	AgeConfirmed bool   `json:"age_confirmed,omitempty"`
}

func (p pendingSignIn) login() ExternalLogin {
	return ExternalLogin{
		Provider:  p.Provider,
		Subject:   p.Subject,
		Email:     p.Email,
		Name:      p.Name,
		Username:  p.Username,
		AvatarURL: p.AvatarURL,
	}
}

func (sl *socialLogin) verifyCookieName() string { return sl.ageCookie(verifyEmailCookie) }

// verifyBinding is the token binding of a pending sign-in: a hash of its
// browser cookie, so the stored row cannot be turned back into the cookie.
func verifyBinding(cookie string) string { return "login:" + hashSessionToken(cookie) }

// verifyCSRF derives the verify-email forms' token from the pending
// sign-in's cookie, which a cross-site page cannot read.
func verifyCSRF(cookie string) string {
	mac := hmac.New(sha256.New, []byte(cookie))
	mac.Write([]byte("systemauth-verify-email-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// canVerifyEmail reports whether an unverified login can be held for
// verification: mail is configured and the provider gave an address.
func (sl *socialLogin) canVerifyEmail(login ExternalLogin) bool {
	if sl.mail == nil || login.Email == "" {
		return false
	}
	_, err := omnimail.ParseAddress(login.Email)
	return err == nil
}

// startEmailVerification holds login as a pending sign-in bound to this
// browser, mails a verification link to its address and sends the browser
// to the verify-email page. The page reads the same whether or not the
// message was sent.
func (sl *socialLogin) startEmailVerification(ctx context.Context, w http.ResponseWriter, r *http.Request, login ExternalLogin, redirectURL string) {
	logger := LoggerFromContext(ctx)
	decision := sl.mail.allowSend(w, r, login.Email)
	if decision == sendRefused || decision == sendFailed {
		return
	}
	cookie, err := newSessionToken()
	if err != nil {
		logger.Error("starting email verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := json.Marshal(pendingSignIn{
		Provider:     login.Provider,
		Subject:      login.Subject,
		Email:        login.Email,
		Name:         login.Name,
		Username:     login.Username,
		AvatarURL:    login.AvatarURL,
		RedirectURL:  redirectURL,
		AgeConfirmed: ageConfirmed(ctx),
	})
	if err != nil {
		logger.Error("starting email verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := sl.issueSignInToken(ctx, cookie, login.Email, data, decision); err != nil {
		logger.Error("starting email verification", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	logger.Info("sign-in held for email verification", "provider", login.Provider)
	http.SetCookie(w, sl.cookies.cookie(sl.verifyCookieName(), cookie, int(sl.mail.ttl.Seconds())))
	http.Redirect(w, r, VerifyEmailPath, http.StatusSeeOther)
}

// issueSignInToken stores a verification token for the pending sign-in
// bound to cookie and, when the send limits allow, mails its link. A
// delivery failure is logged, not returned: the person sees the same page
// and can ask for another link.
func (sl *socialLogin) issueSignInToken(ctx context.Context, cookie, email string, data []byte, decision sendDecision) error {
	token, err := newSessionToken()
	if err != nil {
		return err
	}
	now := sl.now()
	if err := sl.verifyTokens.Create(ctx, token, VerificationToken{
		Purpose:   PurposeVerifyEmail,
		Email:     email,
		Binding:   verifyBinding(cookie),
		Data:      data,
		CreatedAt: now,
		ExpiresAt: now.Add(sl.mail.ttl),
	}); err != nil {
		return err
	}
	sent := false
	if decision == sendAllowed {
		if err := sl.mail.send(ctx, mailVerifySignIn, email, mailData{Link: sl.mail.link(VerifyEmailConfirmPath, token)}); err != nil {
			LoggerFromContext(ctx).Error("sending verification mail", "purpose", PurposeVerifyEmail, "error", err)
		} else {
			sent = true
		}
	}
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailVerificationSent,
		Action:    "send_verification",
		Actor:     audit.Actor{Type: actorPrincipal},
		Resource:  audit.Resource{Type: "email"},
		Details:   details("purpose", string(PurposeVerifyEmail), "sent", sent),
	})
	return nil
}

var verifyEmailTemplate = template.Must(template.New("verify-email").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title></head>
<body><main><h1>{{.Title}}</h1>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
{{if .Email}}<p>We sent a link to <strong>{{.Email}}</strong>. Open it in this browser to finish signing in. It works once and expires in {{.ExpiresIn}}.</p>
<form method="post" action="{{.ResendAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit">Send another link</button>
</form>{{end}}
{{if .Token}}<p>Confirm that you want to use this email address to sign in.</p>
<form method="post" action="{{.ConfirmAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit">Verify and continue</button>
</form>{{end}}
{{if .Restart}}<p><a href="{{.LoginPath}}">Sign in again</a></p>{{end}}
</main></body></html>
`))

type verifyEmailView struct {
	Title, Message                         string
	Email, ExpiresIn, CSRF, Token          string
	ResendAction, ConfirmAction, LoginPath string
	Restart                                bool
	status                                 int
	formTargetsAnyOrigin                   bool
}

func (sl *socialLogin) renderVerifyEmail(w http.ResponseWriter, r *http.Request, v verifyEmailView) {
	noStore(w)
	if v.Title == "" {
		v.Title = "Verify your email address"
	}
	v.ResendAction, v.ConfirmAction, v.LoginPath = VerifyEmailResendPath, VerifyEmailConfirmPath, LoginPath
	if v.formTargetsAnyOrigin {
		// Confirming completes the sign-in, which redirects to wherever
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
	if err := verifyEmailTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering verify-email page", "error", err)
	}
}

// expiredVerifyView is shown when the browser has no usable pending
// sign-in.
func expiredVerifyView() verifyEmailView {
	return verifyEmailView{
		Title:   "Sign in again",
		Message: "This sign-in has expired or was completed. Sign in again to get a new link.",
		Restart: true,
		status:  http.StatusBadRequest,
	}
}

// pendingFor returns the browser's pending sign-in cookie and its newest
// usable token, or ok false when there is none (the page is answered).
func (sl *socialLogin) pendingFor(w http.ResponseWriter, r *http.Request) (string, *VerificationToken, bool) {
	cookie := cookieValue(r, sl.verifyCookieName())
	if cookie == "" {
		sl.renderVerifyEmail(w, r, expiredVerifyView())
		return "", nil, false
	}
	t, err := sl.verifyTokens.Latest(r.Context(), PurposeVerifyEmail, verifyBinding(cookie))
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenNotFound) {
			LoggerFromContext(r.Context()).Error("reading pending sign-in", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return "", nil, false
		}
		sl.renderVerifyEmail(w, r, expiredVerifyView())
		return "", nil, false
	}
	return cookie, t, true
}

// handleVerifyEmailPage serves GET /login/verify-email.
func (sl *socialLogin) handleVerifyEmailPage(w http.ResponseWriter, r *http.Request) {
	cookie, t, ok := sl.pendingFor(w, r)
	if !ok {
		return
	}
	v := verifyEmailView{Email: t.Email, ExpiresIn: humanDuration(sl.mail.ttl), CSRF: verifyCSRF(cookie)}
	if r.URL.Query().Get("resent") != "" {
		v.Message = "If we could, we sent another link. Check your inbox and spam folder."
	}
	sl.renderVerifyEmail(w, r, v)
}

// checkVerifyForm checks a verify-email form submission: its origin, its
// size and the CSRF token derived from the pending sign-in's cookie. It
// returns the cookie, or "" when it answered the request.
func (sl *socialLogin) checkVerifyForm(w http.ResponseWriter, r *http.Request) string {
	noStore(w)
	if !sl.redirects.fromIssuer(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return ""
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return ""
	}
	cookie := cookieValue(r, sl.verifyCookieName())
	if cookie == "" {
		sl.renderVerifyEmail(w, r, expiredVerifyView())
		return ""
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")), []byte(verifyCSRF(cookie))) != 1 {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return ""
	}
	return cookie
}

// handleVerifyEmailResend serves POST /login/verify-email/resend: it
// revokes the pending sign-in's links and mails a new one, within the send
// limits, answering the same way whether or not it was sent.
func (sl *socialLogin) handleVerifyEmailResend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	if sl.checkVerifyForm(w, r) == "" {
		return
	}
	cookie, t, ok := sl.pendingFor(w, r)
	if !ok {
		return
	}
	decision := sl.mail.allowSend(w, r, t.Email)
	if decision == sendRefused || decision == sendFailed {
		return
	}
	if _, err := sl.verifyTokens.Revoke(ctx, PurposeVerifyEmail, verifyBinding(cookie)); err != nil {
		logger.Error("revoking verification links", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := sl.issueSignInToken(ctx, cookie, t.Email, t.Data, decision); err != nil {
		logger.Error("resending verification link", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, sl.cookies.cookie(sl.verifyCookieName(), cookie, int(sl.mail.ttl.Seconds())))
	http.Redirect(w, r, VerifyEmailPath+"?resent=1", http.StatusSeeOther)
}

// handleVerifyEmailConfirmPage serves GET /login/verify-email/confirm, the
// mailed link. It uses nothing: it shows a form whose POST does, so a mail
// scanner that fetches the link cannot use the token.
func (sl *socialLogin) handleVerifyEmailConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	cookie := cookieValue(r, sl.verifyCookieName())
	if token == "" || len(token) > 256 || cookie == "" {
		sl.renderVerifyEmail(w, r, verifyEmailView{
			Title:   "Open the link in the browser you signed in with",
			Message: "This link finishes a sign-in only in the browser where it started, and only once. Open it there, or sign in again to get a new link.",
			Restart: true,
			status:  http.StatusBadRequest,
		})
		return
	}
	sl.renderVerifyEmail(w, r, verifyEmailView{Token: token, CSRF: verifyCSRF(cookie), formTargetsAnyOrigin: true})
}

// handleVerifyEmailConfirm serves POST /login/verify-email/confirm. The
// token is used only together with the cookie of the browser whose sign-in
// it was issued for; on success the address counts as proven and the held
// sign-in completes through ResolveExternalLogin.
func (sl *socialLogin) handleVerifyEmailConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	cookie := sl.checkVerifyForm(w, r)
	if cookie == "" {
		return
	}
	binding := verifyBinding(cookie)
	t, err := sl.verifyTokens.Consume(ctx, r.PostForm.Get("token"), PurposeVerifyEmail, binding)
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenInvalid) {
			logger.Error("using verification link", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		sl.signInRefused(ctx, "", "", "verification_invalid")
		sl.renderVerifyEmail(w, r, verifyEmailView{
			Title:   "This link cannot be used",
			Message: "The link is invalid, has expired, was replaced by a newer one or was already used. Sign in again to get a new link.",
			Restart: true,
			status:  http.StatusBadRequest,
		})
		return
	}
	// The sign-in is decided now: older links of this browser go too.
	if _, err := sl.verifyTokens.Revoke(ctx, PurposeVerifyEmail, binding); err != nil {
		logger.Warn("revoking remaining verification links", "error", err)
	}
	http.SetCookie(w, sl.cookies.cookie(sl.verifyCookieName(), "", -1))

	var pending pendingSignIn
	if err := json.Unmarshal(t.Data, &pending); err != nil {
		logger.Error("reading pending sign-in", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if pending.Provider == "" || pending.Subject == "" {
		logger.Error("reading pending sign-in", "error", "the pending sign-in has no provider identity")
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	login := pending.login()
	login.Email = t.Email
	login.EmailProven = true
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailVerified,
		Action:    "verify_email",
		Actor:     audit.Actor{Type: actorPrincipal},
		Resource:  audit.Resource{Type: "email"},
		Details:   details("purpose", string(PurposeVerifyEmail), "method", login.Provider),
	})

	ctx = sl.withSignupCode(ctx, r)
	if pending.AgeConfirmed {
		ctx = withAgeConfirmed(ctx)
	}
	p, err := ResolveExternalLogin(ctx, sl.directory, login, sl.now())
	sl.completeSignIn(ctx, w, r, login.Provider, pending.RedirectURL, p, err)
}
