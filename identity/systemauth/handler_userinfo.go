package systemauth

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/ory/fosite"
)

// UserInfoPath is the OpenID Connect UserInfo endpoint (OIDC Core §5.3).
const UserInfoPath = "/oauth/userinfo"

// scopeClaims maps the standard OIDC scopes to the claims they release
// (OIDC Core §5.4). Standard claims are only returned when their scope was
// granted to the access token.
var scopeClaims = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// claimScope is the reverse of scopeClaims.
var claimScope = func() map[string]string {
	m := map[string]string{}
	for scope, claims := range scopeClaims {
		for _, c := range claims {
			m[c] = scope
		}
	}
	return m
}()

// UserInfoClaims filters claims to those releasable under granted: "sub"
// is always subject; a standard claim is kept only when its scope was
// granted; other (non-standard) claims returned by the SessionProvider are
// passed through, since the provider already chose them by scope.
func UserInfoClaims(subject string, claims map[string]any, granted []string) map[string]any {
	grantedSet := make(map[string]bool, len(granted))
	for _, s := range granted {
		grantedSet[s] = true
	}
	out := map[string]any{}
	for k, v := range claims {
		if scope, standard := claimScope[k]; standard && !grantedSet[scope] {
			continue
		}
		out[k] = v
	}
	out["sub"] = subject
	return out
}

// bearerChallenge is an RFC 6750 §3 Bearer challenge.
func bearerChallenge(code, description, scope string) string {
	challenge := `Bearer realm="systemauth"`
	if code != "" {
		challenge += `, error="` + code + `"`
	}
	if description != "" {
		challenge += `, error_description="` + description + `"`
	}
	if scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	return challenge
}

// writeBearerError writes an RFC 6750 §3 error with its WWW-Authenticate
// challenge.
func writeBearerError(w http.ResponseWriter, status int, code, description, scope string) {
	writeChallengeError(w, status, []string{bearerChallenge(code, description, scope)}, code, description)
}

// writeScopeError writes a 403 insufficient_scope error for the access
// token of ar, challenging with the scheme the token is used with.
func writeScopeError(w http.ResponseWriter, ar fosite.AccessRequester, description, scope string) {
	if sess, ok := ar.GetSession().(*Session); ok && sess.DPoPJKT != "" {
		c := dpopChallenge("insufficient_scope", description)
		if scope != "" {
			c += `, scope="` + scope + `"`
		}
		writeChallengeError(w, http.StatusForbidden, []string{c}, "insufficient_scope", description)
		return
	}
	writeBearerError(w, http.StatusForbidden, "insufficient_scope", description, scope)
}

// writeChallengeError writes an error response with WWW-Authenticate
// challenges and, when code is set, an error body.
func writeChallengeError(w http.ResponseWriter, status int, challenges []string, code, description string) {
	for _, c := range challenges {
		w.Header().Add("WWW-Authenticate", c)
	}
	w.Header().Set("Cache-Control", "no-store")
	if code == "" {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status line and challenge are already written; an encoding
	// failure here can only be a broken connection.
	if err := json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description}); err != nil {
		return
	}
}

// userinfoEndpoint serves GET/POST /oauth/userinfo.
func (s *Server) userinfoEndpoint(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)

	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	ar, authErr := s.authenticateAccessToken(r, s.endpointURL(UserInfoPath))
	if authErr != nil {
		logger.Debug("userinfo: access token refused", "error", authErr)
		s.writeTokenAuthError(w, authErr)
		return
	}
	granted := ar.GetGrantedScopes()
	subject := sessionSubject(ar.GetSession())
	if !granted.Has("openid") || subject == "" {
		writeScopeError(w, ar, "The access token was not granted the openid scope.", "openid")
		return
	}

	userClaims, err := s.addOrgsClaims(ctx, subject, s.sessionProvider.GetUserClaims(ctx, subject, granted), false)
	if err != nil {
		logger.Error("userinfo: reading organizations", "error", err)
		http.Error(w, "could not read organizations", http.StatusInternalServerError)
		return
	}
	claims := UserInfoClaims(subject, userClaims, granted)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		logger.Error("writing userinfo response", "error", err)
	}
}

// UserInfoInput documents the UserInfo request for OpenAPI.
type UserInfoInput struct {
	Authorization string `header:"Authorization" doc:"DPoP <token> for a DPoP-bound access token (with a DPoP proof header), or Bearer <token> for an unbound one; granted the openid scope"`
}

// UserInfoOutput documents the UserInfo response for OpenAPI.
type UserInfoOutput struct {
	Body map[string]any
}

// registerUserInfoOperation documents /oauth/userinfo. The handler itself
// is served by fositeInterceptor.
func (s *Server) registerUserInfoOperation() {
	huma.Register(s.huma, huma.Operation{
		OperationID: "userinfo",
		Method:      http.MethodGet,
		Path:        UserInfoPath,
		Summary:     "OpenID Connect UserInfo",
		Description: "Returns claims about the authenticated end-user for an access token granted the openid scope (OIDC Core 5.3); a DPoP-bound token needs the DPoP scheme and a DPoP proof (RFC 9449). Standard claims are released per granted scope: email (email, email_verified), profile (name, picture, ...). Invalid tokens get 401 with a WWW-Authenticate challenge.",
		Tags:        []string{"OpenID Connect"},
	}, func(_ context.Context, _ *UserInfoInput) (*UserInfoOutput, error) {
		return &UserInfoOutput{}, nil
	})
}
