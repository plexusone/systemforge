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
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/plexusone/omnimail"

	"github.com/plexusone/systemforge/contract/audit"
)

// Email change routes, mounted with social login when mail is configured
// and the principal directory can change emails (PrincipalEmailChanger).
// Every route needs the SystemAuth login session.
const (
	// AccountEmailPath shows the signed-in person's email, a pending
	// change, and the form to request one (GET); POST requests a change.
	AccountEmailPath = "/account/email"
	// AccountEmailCancelPath cancels the pending change (POST).
	AccountEmailCancelPath = "/account/email/cancel"
	// AccountEmailConfirmPath is the link mailed to the new address: GET
	// shows a confirmation form, POST uses the token and changes the email.
	AccountEmailConfirmPath = "/account/email/confirm"
)

// Security event types of email change.
const (
	// EventEmailChangeRequested records a requested email change.
	EventEmailChangeRequested = "systemauth.email_change.requested"
	// EventEmailChangeCancelled records a cancelled pending change.
	EventEmailChangeCancelled = "systemauth.email_change.cancelled"
	// EventEmailChanged records a principal's email changed to a proven
	// address.
	EventEmailChanged = "systemauth.email.changed"
)

// pendingEmailChange is kept in an email_change token's Data.
type pendingEmailChange struct {
	// From is the email the change was requested from; the change is made
	// only while it is still the principal's email.
	From string `json:"from"`
}

// emailChangeBinding binds a change to its principal: only a session of
// that principal can confirm it.
func emailChangeBinding(id uuid.UUID) string { return "principal:" + id.String() }

// emailChangeCSRF derives the account email forms' token from the login
// session token.
func emailChangeCSRF(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte("systemauth-email-change-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

var accountEmailTemplate = template.Must(template.New("account-email").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title></head>
<body><main><h1>{{.Title}}</h1>
{{if .Message}}<p role="status">{{.Message}}</p>{{end}}
{{if .Token}}<p>Confirm that you want to use this address for your account.</p>
<form method="post" action="{{.ConfirmAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<input type="hidden" name="token" value="{{.Token}}">
<button type="submit">Use this address</button>
</form>{{else if .Account}}
<p>Your email address: <strong>{{.Email}}</strong>{{if .Verified}} (verified){{end}}</p>
{{if .Pending}}<p>A change to <strong>{{.Pending}}</strong> is waiting for confirmation from that address.</p>
<form method="post" action="{{.CancelAction}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit">Cancel the change</button>
</form>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<label for="email">New email address</label>
<input id="email" name="email" type="email" required autocomplete="email" maxlength="254">
<button type="submit">Send a confirmation link</button>
</form>{{end}}
{{if .SignIn}}<p><a href="{{.SignIn}}">Sign in</a></p>{{end}}
</main></body></html>
`))

type accountEmailView struct {
	Title, Message, Email, Pending, CSRF, Token, SignIn string
	Action, CancelAction, ConfirmAction                 string
	Verified, Account                                   bool
	status                                              int
}

func (sl *socialLogin) renderAccountEmail(w http.ResponseWriter, r *http.Request, v accountEmailView) {
	noStore(w)
	if v.Title == "" {
		v.Title = "Email address"
	}
	v.Action, v.CancelAction, v.ConfirmAction = AccountEmailPath, AccountEmailCancelPath, AccountEmailConfirmPath
	if v.status == 0 {
		v.status = http.StatusOK
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(v.status)
	if err := accountEmailTemplate.Execute(w, v); err != nil {
		LoggerFromContext(r.Context()).Error("rendering account email page", "error", err)
	}
}

// accountPrincipal returns the signed-in principal and its session token,
// or answers the request: a person who is not signed in is asked to sign
// in and come back to returnTo, which carries no token.
func (sl *socialLogin) accountPrincipal(w http.ResponseWriter, r *http.Request, returnTo string) (*HumanPrincipal, string, bool) {
	ctx := r.Context()
	sess, token, err := sl.sessionWithToken(r)
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			LoggerFromContext(ctx).Error("reading login session", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return nil, "", false
		}
		sl.renderAccountEmail(w, r, accountEmailView{
			Title:   "Sign in to continue",
			Message: "Sign in to manage your email address. If you followed a confirmation link, open it again after signing in.",
			SignIn:  LoginPath + "?return_to=" + url.QueryEscape(returnTo),
			status:  http.StatusUnauthorized,
		})
		return nil, "", false
	}
	p, err := sl.directory.GetPrincipal(ctx, sess.PrincipalID)
	if err != nil {
		LoggerFromContext(ctx).Error("loading principal", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return nil, "", false
	}
	if p.Managed {
		sl.renderAccountEmail(w, r, accountEmailView{
			Title:   "Email address",
			Message: "The people who manage your account manage its email address.",
			status:  http.StatusForbidden,
		})
		return nil, "", false
	}
	return p, token, true
}

// checkAccountForm checks an account email form: its origin, its size and
// the CSRF token derived from the login session. It returns the
// principal, or ok false when it answered the request.
func (sl *socialLogin) checkAccountForm(w http.ResponseWriter, r *http.Request) (*HumanPrincipal, bool) {
	noStore(w)
	if !sl.redirects.fromIssuer(r) {
		http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return nil, false
	}
	p, token, ok := sl.accountPrincipal(w, r, AccountEmailPath)
	if !ok {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")), []byte(emailChangeCSRF(token))) != 1 {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return nil, false
	}
	return p, true
}

// handleAccountEmailPage serves GET /account/email.
func (sl *socialLogin) handleAccountEmailPage(w http.ResponseWriter, r *http.Request) {
	p, token, ok := sl.accountPrincipal(w, r, AccountEmailPath)
	if !ok {
		return
	}
	v := accountEmailView{Account: true, Email: p.Email, Verified: p.EmailVerified, CSRF: emailChangeCSRF(token)}
	t, err := sl.verifyTokens.Latest(r.Context(), PurposeEmailChange, emailChangeBinding(p.ID))
	switch {
	case err == nil:
		v.Pending = t.Email
	case !errors.Is(err, ErrVerificationTokenNotFound):
		LoggerFromContext(r.Context()).Error("reading pending email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	switch {
	case q.Get("requested") != "":
		v.Message = "If the address can receive mail, we sent it a confirmation link. Your email changes only when the link is used."
	case q.Get("cancelled") != "":
		v.Message = "The change was cancelled."
	case q.Get("changed") != "":
		v.Message = "Your email address was changed."
	}
	sl.renderAccountEmail(w, r, v)
}

// handleAccountEmailRequest serves POST /account/email. It mails a link to
// the new address and a notice to the current one, and answers the same
// whether or not the address belongs to an account, could be sent to, or
// was within its send limit.
func (sl *socialLogin) handleAccountEmailRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	p, ok := sl.checkAccountForm(w, r)
	if !ok {
		return
	}
	addr, err := omnimail.ParseAddress(strings.TrimSpace(r.PostForm.Get("email")))
	if err != nil || addr.Name != "" || len(addr.Email) > 254 {
		sl.renderAccountEmail(w, r, accountEmailView{Message: "Enter a valid email address.", status: http.StatusBadRequest})
		return
	}
	newEmail := addr.Email
	if strings.EqualFold(newEmail, p.Email) {
		sl.renderAccountEmail(w, r, accountEmailView{Message: "That is already your email address.", status: http.StatusBadRequest})
		return
	}
	decision := sl.mail.allowSend(w, r, newEmail)
	if decision == sendRefused || decision == sendFailed {
		return
	}
	binding := emailChangeBinding(p.ID)
	// One pending change at a time: a new request replaces the last.
	if _, err := sl.verifyTokens.Revoke(ctx, PurposeEmailChange, binding); err != nil {
		logger.Error("revoking pending email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data, err := json.Marshal(pendingEmailChange{From: p.Email})
	if err != nil {
		logger.Error("requesting email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	token, err := newSessionToken()
	if err != nil {
		logger.Error("requesting email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	now := sl.now()
	if err := sl.verifyTokens.Create(ctx, token, VerificationToken{
		Purpose:     PurposeEmailChange,
		Email:       newEmail,
		PrincipalID: p.ID,
		Binding:     binding,
		Data:        data,
		CreatedAt:   now,
		ExpiresAt:   now.Add(sl.mail.ttl),
	}); err != nil {
		logger.Error("requesting email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sent := false
	if decision == sendAllowed {
		sent = sl.sendLogged(ctx, mailVerifyChange, newEmail, mailData{Link: sl.mail.link(AccountEmailConfirmPath, token)})
		if p.Email != "" {
			sl.sendLogged(ctx, mailChangeRequested, p.Email, mailData{
				NewEmail:   maskEmail(newEmail),
				AccountURL: sl.mail.issuer + AccountEmailPath,
			})
		}
	}
	actor := audit.Actor{ID: p.ID, Type: actorPrincipal}
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailVerificationSent,
		Action:    "send_verification",
		Actor:     actor,
		Resource:  audit.Resource{Type: "email"},
		Details:   details("purpose", string(PurposeEmailChange), "sent", sent),
	})
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailChangeRequested,
		Action:    "request_email_change",
		Actor:     actor,
		Resource:  audit.Resource{Type: "principal", ID: p.ID},
	})
	http.Redirect(w, r, AccountEmailPath+"?requested=1", http.StatusSeeOther)
}

// sendLogged sends a message and logs a failure, reporting whether it was
// sent. Responses never depend on it.
func (sl *socialLogin) sendLogged(ctx context.Context, kind mailKind, to string, data mailData) bool {
	if err := sl.mail.send(ctx, kind, to, data); err != nil {
		LoggerFromContext(ctx).Error("sending mail", "kind", kind, "error", err)
		return false
	}
	return true
}

// handleAccountEmailCancel serves POST /account/email/cancel.
func (sl *socialLogin) handleAccountEmailCancel(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, ok := sl.checkAccountForm(w, r)
	if !ok {
		return
	}
	n, err := sl.verifyTokens.Revoke(ctx, PurposeEmailChange, emailChangeBinding(p.ID))
	if err != nil {
		LoggerFromContext(ctx).Error("cancelling email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n > 0 {
		sl.emit(ctx, &audit.Event{
			EventType: EventEmailChangeCancelled,
			Action:    "cancel_email_change",
			Actor:     audit.Actor{ID: p.ID, Type: actorPrincipal},
			Resource:  audit.Resource{Type: "principal", ID: p.ID},
		})
	}
	http.Redirect(w, r, AccountEmailPath+"?cancelled=1", http.StatusSeeOther)
}

// handleAccountEmailConfirmPage serves GET /account/email/confirm, the
// link mailed to the new address. It uses nothing; its form does.
func (sl *socialLogin) handleAccountEmailConfirmPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" || len(token) > 256 {
		sl.renderAccountEmail(w, r, accountEmailView{Message: "This link is incomplete.", status: http.StatusBadRequest})
		return
	}
	_, session, ok := sl.accountPrincipal(w, r, AccountEmailPath)
	if !ok {
		return
	}
	sl.renderAccountEmail(w, r, accountEmailView{Title: "Confirm your new email address", Token: token, CSRF: emailChangeCSRF(session)})
}

// handleAccountEmailConfirm serves POST /account/email/confirm. The token
// is used only by a session of the principal that requested the change;
// the email changes, marked verified, only if it is still the one the
// change was requested from and no other account has the new address.
func (sl *socialLogin) handleAccountEmailConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	p, ok := sl.checkAccountForm(w, r)
	if !ok {
		return
	}
	cannot := func(msg string) {
		sl.renderAccountEmail(w, r, accountEmailView{Title: "The email address was not changed", Message: msg, status: http.StatusBadRequest})
	}
	t, err := sl.verifyTokens.Consume(ctx, r.PostForm.Get("token"), PurposeEmailChange, emailChangeBinding(p.ID))
	if err != nil {
		if !errors.Is(err, ErrVerificationTokenInvalid) {
			logger.Error("using email change link", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		cannot("The link is invalid, has expired, was cancelled or replaced, was already used, or belongs to another account. Request the change again.")
		return
	}
	var pending pendingEmailChange
	if err := json.Unmarshal(t.Data, &pending); err != nil {
		logger.Error("reading pending email change", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	err = sl.emailChanger.ChangeEmail(ctx, p.ID, pending.From, t.Email, sl.now())
	switch {
	case errors.Is(err, ErrEmailConflict):
		cannot("This address cannot be used for your account.")
		return
	case errors.Is(err, ErrEmailChangeStale):
		cannot("Your email address changed after this link was sent. Request the change again.")
		return
	case err != nil:
		logger.Error("changing email", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if pending.From != "" {
		sl.sendLogged(ctx, mailChanged, pending.From, mailData{NewEmail: maskEmail(t.Email)})
	}
	actor := audit.Actor{ID: p.ID, Type: actorPrincipal}
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailVerified,
		Action:    "verify_email",
		Actor:     actor,
		Resource:  audit.Resource{Type: "email"},
		Details:   details("purpose", string(PurposeEmailChange)),
	})
	sl.emit(ctx, &audit.Event{
		EventType: EventEmailChanged,
		Action:    "change_email",
		Actor:     actor,
		Resource:  audit.Resource{Type: "principal", ID: p.ID},
	})
	logger.Info("email changed", "principal_id", p.ID)
	http.Redirect(w, r, AccountEmailPath+"?changed=1", http.StatusSeeOther)
}
