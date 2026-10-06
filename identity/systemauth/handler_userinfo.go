package systemauth

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"strings"

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

// bearerToken extracts an access token per RFC 6750 §2.1 (Authorization
// header) or §2.2 (form-encoded POST body). Query parameters are not
// accepted.
func bearerToken(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, token, ok := strings.Cut(auth, " ")
		if ok && strings.EqualFold(scheme, "Bearer") {
			return strings.TrimSpace(token)
		}
		return ""
	}
	if r.Method == http.MethodPost {
		ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err == nil && ct == "application/x-www-form-urlencoded" {
			return r.PostFormValue("access_token")
		}
	}
	return ""
}

// writeBearerError writes an RFC 6750 §3 error with its WWW-Authenticate
// challenge.
func writeBearerError(w http.ResponseWriter, status int, code, description, scope string) {
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
	w.Header().Set("WWW-Authenticate", challenge)
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
	token := bearerToken(r)
	if token == "" {
		writeBearerError(w, http.StatusUnauthorized, "", "", "")
		return
	}

	_, ar, err := s.oauth2.IntrospectToken(ctx, token, fosite.AccessToken, s.Session(""))
	if err != nil {
		logger.Debug("userinfo: invalid access token", "error", err)
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired or revoked.", "")
		return
	}
	granted := ar.GetGrantedScopes()
	subject := sessionSubject(ar.GetSession())
	if !granted.Has("openid") || subject == "" {
		writeBearerError(w, http.StatusForbidden, "insufficient_scope", "The access token was not granted the openid scope.", "openid")
		return
	}

	claims := UserInfoClaims(subject, s.sessionProvider.GetUserClaims(ctx, subject, granted), granted)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(claims); err != nil {
		logger.Error("writing userinfo response", "error", err)
	}
}

// UserInfoInput documents the UserInfo request for OpenAPI.
type UserInfoInput struct {
	Authorization string `header:"Authorization" doc:"Bearer access token granted the openid scope"`
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
		Description: "Returns claims about the authenticated end-user for a bearer access token granted the openid scope (OIDC Core 5.3). Standard claims are released per granted scope: email (email, email_verified), profile (name, picture, ...). Invalid tokens get 401 with a WWW-Authenticate challenge.",
		Tags:        []string{"OpenID Connect"},
	}, func(_ context.Context, _ *UserInfoInput) (*UserInfoOutput, error) {
		return &UserInfoOutput{}, nil
	})
}
