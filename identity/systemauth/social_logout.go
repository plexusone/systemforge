package systemauth

import (
	"errors"
	"html/template"
	"net/http"
)

// LogoutPath ends the SystemAuth login session. GET renders a confirmation
// form; POST (same-origin or from an allowed relying-party origin) deletes
// the __Host-sf_login session, revokes the principal's OAuth tokens and
// redirects to the validated return_to (default: social_login.default_redirect).
const LogoutPath = "/logout"

var logoutTemplate = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign out</title></head>
<body><main><h1>Sign out</h1>
<form method="post" action="/logout">
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
<button type="submit">Sign out</button>
</form></main></body></html>
`))

// frameDeny forbids rendering a page inside a frame (clickjacking).
func frameDeny(w http.ResponseWriter) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
}

// handleLogoutPage serves GET /logout.
func (sl *socialLogin) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	frameDeny(w)
	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" {
		if _, err := sl.redirects.validate(returnTo); err != nil {
			http.Error(w, "invalid return_to", http.StatusBadRequest)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := logoutTemplate.Execute(w, struct{ ReturnTo string }{returnTo}); err != nil {
		LoggerFromContext(r.Context()).Error("rendering logout page", "error", err)
	}
}

// handleLogout serves POST /logout.
//
// CSRF: the request must come from a page on the issuer's origin or an
// allowed relying-party origin (Origin/Referer check); the login cookie is
// SameSite=Lax, so a cross-site POST would not carry it anyway.
func (sl *socialLogin) handleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)

	if !sl.redirects.fromTrustedOrigin(r) {
		http.Error(w, "cross-origin logout rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	target, err := sl.redirects.resolve(r.Form.Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}

	if token := cookieValue(r, sl.cookies.sessionName); token != "" {
		sess, err := sl.sessions.Get(ctx, token)
		switch {
		case err == nil:
			if err := sl.sessions.Delete(ctx, token); err != nil {
				logger.Error("deleting login session", "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if err := sl.revokePrincipalTokens(r, sess.PrincipalID.String()); err != nil {
				logger.Error("revoking tokens on logout", "principal_id", sess.PrincipalID, "error", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			logger.Info("logout", "principal_id", sess.PrincipalID)
		case errors.Is(err, ErrLoginSessionNotFound):
			// Already signed out or expired; still clear the cookie.
		default:
			logger.Error("reading login session", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	sl.cookies.clearSession(w)

	//nolint:gosec // G710: target was validated against the redirect allowlist
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// revokePrincipalTokens revokes every access and refresh token issued to
// subject, through the storage's revocation support.
func (sl *socialLogin) revokePrincipalTokens(r *http.Request, subject string) error {
	if sl.revoker == nil {
		LoggerFromContext(r.Context()).Warn("storage cannot revoke tokens by subject; tokens stay valid until they expire")
		return nil
	}
	return sl.revoker.RevokeSubjectTokens(r.Context(), subject)
}
