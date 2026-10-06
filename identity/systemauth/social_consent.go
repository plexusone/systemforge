package systemauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/ory/fosite"
)

// ConsentPath is the consent page. /oauth/authorize sends a signed-in user
// here (with the authorization URL as return_to) when the client has not
// been granted the requested scopes and social_login.skip_consent is off.
const ConsentPath = "/consent"

// authorizePath is the only target a consent decision may return to.
const authorizePath = "/oauth/authorize"

var scopeDescriptions = map[string]string{
	"openid":         "Confirm your identity",
	"profile":        "Read your name and profile picture",
	"email":          "Read your email address",
	"offline_access": "Stay signed in (refresh tokens)",
}

var consentTemplate = template.Must(template.New("consent").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize {{.ClientName}}</title></head>
<body><main><h1>{{.ClientName}} wants to access your account</h1>
<ul>
{{range .Scopes}}<li>{{.}}</li>
{{end}}</ul>
<form method="post" action="/consent">
<input type="hidden" name="return_to" value="{{.ReturnTo}}">
<input type="hidden" name="csrf_token" value="{{.CSRF}}">
<button type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button>
</form></main></body></html>
`))

// consentTarget is a parsed authorization request awaiting consent.
type consentTarget struct {
	raw      string
	clientID string
	scopes   []string
}

// parseConsentTarget accepts only a same-origin /oauth/authorize URL.
func parseConsentTarget(raw string) (*consentTarget, error) {
	if raw == "" || len(raw) > 4096 || !strings.HasPrefix(raw, authorizePath+"?") {
		return nil, ErrRedirectNotAllowed
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != authorizePath || u.Host != "" || u.Scheme != "" {
		return nil, ErrRedirectNotAllowed
	}
	q := u.Query()
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, ErrRedirectNotAllowed
	}
	return &consentTarget{raw: u.String(), clientID: clientID, scopes: strings.Fields(q.Get("scope"))}, nil
}

// consentCSRF derives the consent form token from the login session token:
// it is bound to the session, and a cross-site page cannot compute it
// because the session cookie is HttpOnly.
func consentCSRF(sessionToken string) string {
	mac := hmac.New(sha256.New, []byte(sessionToken))
	mac.Write([]byte("systemauth-consent-v1"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// sessionWithToken returns the active login session on r and its token.
func (sl *socialLogin) sessionWithToken(r *http.Request) (*LoginSession, string, error) {
	sess, err := sl.currentSession(r)
	if err != nil {
		return nil, "", err
	}
	return sess, cookieValue(r, sl.cookies.sessionName), nil
}

// handleConsentPage serves GET /consent.
func (sl *socialLogin) handleConsentPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)
	frameDeny(w)

	target, err := parseConsentTarget(r.URL.Query().Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	_, token, err := sl.sessionWithToken(r)
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			logger.Error("reading login session", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		//nolint:gosec // G710: same-origin login path; the authorize URL is query-escaped
		http.Redirect(w, r, LoginPath+"?return_to="+url.QueryEscape(target.raw), http.StatusFound)
		return
	}
	client, err := sl.clients.GetClientByID(ctx, target.clientID)
	if err != nil {
		if !errors.Is(err, ErrClientNotFound) {
			logger.Error("loading client for consent", "client_id", target.clientID, "error", err)
		}
		http.Error(w, "unknown client", http.StatusBadRequest)
		return
	}
	name := client.Name
	if name == "" {
		name = client.ID
	}
	scopes := make([]string, 0, len(target.scopes))
	for _, s := range target.scopes {
		if d, ok := scopeDescriptions[s]; ok {
			scopes = append(scopes, d)
		} else {
			scopes = append(scopes, s)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := consentTemplate.Execute(w, struct {
		ClientName, ReturnTo, CSRF string
		Scopes                     []string
	}{name, target.raw, consentCSRF(token), scopes}); err != nil {
		logger.Error("rendering consent page", "error", err)
	}
}

// handleConsent serves POST /consent.
func (sl *socialLogin) handleConsent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	noStore(w)

	if !sl.redirects.fromIssuer(r) {
		http.Error(w, "cross-origin consent rejected", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	target, err := parseConsentTarget(r.PostForm.Get("return_to"))
	if err != nil {
		http.Error(w, "invalid return_to", http.StatusBadRequest)
		return
	}
	sess, token, err := sl.sessionWithToken(r)
	if err != nil {
		if !errors.Is(err, ErrLoginSessionNotFound) {
			logger.Error("reading login session", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		http.Error(w, "not signed in", http.StatusUnauthorized)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf_token")), []byte(consentCSRF(token))) != 1 {
		http.Error(w, "invalid consent token", http.StatusForbidden)
		return
	}

	switch r.PostForm.Get("decision") {
	case "allow":
		if err := sl.consents.SaveConsent(ctx, sess.PrincipalID.String(), target.clientID, target.scopes); err != nil {
			logger.Error("saving consent", "error", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		logger.Info("consent granted", "principal_id", sess.PrincipalID, "client_id", target.clientID, "scopes", target.scopes)
		//nolint:gosec // G710: target is a same-origin /oauth/authorize URL
		http.Redirect(w, r, target.raw, http.StatusSeeOther)
	case "deny":
		logger.Info("consent denied", "principal_id", sess.PrincipalID, "client_id", target.clientID)
		sl.denyAuthorization(ctx, w, target.raw)
	default:
		http.Error(w, "invalid decision", http.StatusBadRequest)
	}
}

// denyAuthorization answers the original authorization request with
// access_denied at the client's (validated) redirect URI.
func (sl *socialLogin) denyAuthorization(ctx context.Context, w http.ResponseWriter, authorizeURL string) {
	// The request is never sent: it only lets Fosite re-parse and validate
	// the original (same-origin) authorization request.
	//nolint:gosec // G704: no outbound request is made
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}
	ar, err := sl.oauth2.NewAuthorizeRequest(ctx, req)
	if err != nil {
		sl.oauth2.WriteAuthorizeError(ctx, w, ar, err)
		return
	}
	sl.oauth2.WriteAuthorizeError(ctx, w, ar, fosite.ErrAccessDenied.WithHint("The resource owner denied the request."))
}
