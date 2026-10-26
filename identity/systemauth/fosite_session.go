package systemauth

import (
	"maps"
	"slices"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// Session is the Fosite session SystemAuth stores with every authorization
// code and token. It carries the OpenID Connect ID-token claims, the claims
// of JWT access tokens (when features.enable_jwt_access_tokens is on) and
// the start of the refresh-token family, which bounds refresh rotation with
// an absolute lifetime.
//
// Session is JSON-serializable so persistent storage can round-trip it.
type Session struct {
	*openid.DefaultSession `json:"oidc"`

	// FamilyIssuedAt is when the grant that started this token family was
	// first exchanged for tokens. Refresh rotation never extends past
	// FamilyIssuedAt + Tokens.RefreshTokenAbsoluteLifetime.
	FamilyIssuedAt time.Time `json:"family_issued_at,omitzero"`

	// AccessClaims are the claims of JWT access tokens.
	AccessClaims *jwt.JWTClaims `json:"access_claims,omitempty"`

	// AccessHeader is the JOSE header of JWT access tokens.
	AccessHeader *jwt.Headers `json:"access_header,omitempty"`

	// DPoPJKT is the RFC 7638 thumbprint of the DPoP key the grant is
	// bound to (RFC 9449). On an authorization code it is the dpop_jkt the
	// authorization request named; on tokens it is the key of the verified
	// proof they were issued with, the access token's cnf.jkt. Refreshing
	// requires a proof by the same key. Empty means unbound bearer tokens.
	DPoPJKT string `json:"dpop_jkt,omitempty"`
}

var (
	_ openid.Session             = (*Session)(nil)
	_ oauth2.JWTSessionContainer = (*Session)(nil)
	_ fosite.ExtraClaimsSession  = (*Session)(nil)
)

// TokenTypeDPoP and TokenTypeBearer are the token_type values of DPoP-bound
// and unbound access tokens.
const (
	TokenTypeDPoP   = "DPoP"
	TokenTypeBearer = "Bearer"
)

// TokenType returns the token_type of the session's access tokens: DPoP
// when they are bound to a key, Bearer otherwise.
func (s *Session) TokenType() string {
	if s.DPoPJKT != "" {
		return TokenTypeDPoP
	}
	return TokenTypeBearer
}

// GetExtraClaims implements fosite.ExtraClaimsSession: introspection
// responses carry the token_type and, for a DPoP-bound token, its cnf.jkt
// (RFC 9449 §6.2), so a resource server introspecting a token knows to
// require a proof by that key.
func (s *Session) GetExtraClaims() map[string]interface{} {
	out := map[string]interface{}{"token_type": s.TokenType()}
	if s.DPoPJKT != "" {
		out["cnf"] = map[string]interface{}{"jkt": s.DPoPJKT}
	}
	return out
}

// GetJWTClaims implements oauth2.JWTSessionContainer. The subject defaults
// to the session subject.
func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	if s.AccessClaims == nil {
		s.AccessClaims = &jwt.JWTClaims{}
	}
	if s.AccessClaims.Subject == "" {
		s.AccessClaims.Subject = sessionSubject(s)
	}
	return s.AccessClaims
}

// GetJWTHeader implements oauth2.JWTSessionContainer.
func (s *Session) GetJWTHeader() *jwt.Headers {
	if s.AccessHeader == nil {
		s.AccessHeader = &jwt.Headers{}
	}
	return s.AccessHeader
}

// Clone implements fosite.Session.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	c := &Session{FamilyIssuedAt: s.FamilyIssuedAt, DPoPJKT: s.DPoPJKT}
	if s.AccessClaims != nil {
		ac := *s.AccessClaims
		ac.Audience = slices.Clone(s.AccessClaims.Audience)
		ac.Scope = slices.Clone(s.AccessClaims.Scope)
		ac.Extra = maps.Clone(s.AccessClaims.Extra)
		c.AccessClaims = &ac
	}
	if s.AccessHeader != nil {
		c.AccessHeader = &jwt.Headers{Extra: maps.Clone(s.AccessHeader.Extra)}
	}
	if s.DefaultSession != nil {
		ds, ok := s.DefaultSession.Clone().(*openid.DefaultSession)
		if !ok {
			// openid.DefaultSession.Clone always returns *openid.DefaultSession.
			panic("systemauth: unexpected openid session clone type")
		}
		c.DefaultSession = ds
	}
	return c
}

// sessionSubject returns the subject of a SystemAuth session, falling back
// to the ID-token subject.
func sessionSubject(sess fosite.Session) string {
	if sess == nil {
		return ""
	}
	if s, ok := sess.(*Session); ok && s.DefaultSession == nil {
		return ""
	}
	if sub := sess.GetSubject(); sub != "" {
		return sub
	}
	if os, ok := sess.(openid.Session); ok && os.IDTokenClaims() != nil {
		return os.IDTokenClaims().Subject
	}
	return ""
}
