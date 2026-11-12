package systemauth

import (
	"errors"
	"fmt"
	"html/template"
	"net/http"
)

// LogoutPath ends the SystemAuth login session. GET renders a confirmation
// form; POST (same-origin or from an allowed relying-party origin) deletes
// the __Host-sf_login session, revokes the principal's OAuth tokens and
// redirects to social_login.managed_signed_out_url for a login token's
// session, else social_login.signed_out_url, else the validated return_to
// (default: social_login.default_redirect).
const LogoutPath = "/logout"

var logoutTemplate = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` + pageStyleLink + `
<title>Sign out</title></head>
<body><main><h1>Sign out</h1>
<form method="post" action="/logout">
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
<button type="submit">Sign out</button>
</form></main></body></html>
`))

// handleLogoutPage serves GET /logout.
func (sl *socialLogin) handleLogoutPage(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	returnTo := r.URL.Query().Get("return_to")
	if returnTo != "" {
		if _, err := sl.redirects.validate(returnTo); err != nil {
			http.Error(w, "invalid return_to", http.StatusBadRequest)
			return
		}
	}
	// Signing out redirects to return_to, an allowed origin.
	allowFormTargets(w, formSources(sl.redirects.originList()...))
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

	sess, ended, err := sl.endSession(w, r)
	if err != nil {
		logger.Error("ending login session", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// The operator's landing for this kind of sign-in, such as the
	// marketing site, or a child's sign-in page.
	target = sl.redirects.signedOutTarget(target, sess, ended)

	//nolint:gosec // G710: target was validated against the redirect allowlist
	http.Redirect(w, r, target, http.StatusSeeOther)
}

// endSession deletes r's login session, revokes the tokens issued to its
// principal and clears the cookie, returning the session it ended. A request
// without a session only has its cookie cleared, and ended is false. The
// caller checks where the request came from.
func (sl *socialLogin) endSession(w http.ResponseWriter, r *http.Request) (sess LoginSession, ended bool, err error) {
	ctx := r.Context()
	if token := cookieValue(r, sl.cookies.sessionName); token != "" {
		sess, err = sl.sessions.Get(ctx, token)
		switch {
		case err == nil:
			if err := sl.sessions.Delete(ctx, token); err != nil {
				return LoginSession{}, false, fmt.Errorf("deleting login session: %w", err)
			}
			if err := sl.revokePrincipalTokens(r, sess.PrincipalID.String()); err != nil {
				return LoginSession{}, false, fmt.Errorf("revoking tokens of %s: %w", sess.PrincipalID, err)
			}
			LoggerFromContext(ctx).Info("logout", "principal_id", sess.PrincipalID)
			sl.signedOut(ctx, sess)
			ended = true
		case errors.Is(err, ErrLoginSessionNotFound):
			// Already signed out or expired; still clear the cookie.
			sess = LoginSession{}
		default:
			return LoginSession{}, false, fmt.Errorf("reading login session: %w", err)
		}
	}
	sl.cookies.clearSession(w)
	return sess, ended, nil
}

// EndLoginSession signs the person on r out of SystemAuth, as POST /logout
// does: it deletes the login session, revokes the tokens issued to its
// principal and clears the cookie. The caller must have checked that the
// request is same-origin.
func (s *Server) EndLoginSession(w http.ResponseWriter, r *http.Request) error {
	if s.social == nil {
		return nil
	}
	_, _, err := s.social.endSession(w, r)
	return err
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
