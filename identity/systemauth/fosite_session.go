package systemauth

import (
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
)

// Session is the Fosite session SystemAuth stores with every authorization
// code and token. It carries the OpenID Connect ID-token claims and the
// start of the refresh-token family, which bounds refresh rotation with an
// absolute lifetime.
//
// Session is JSON-serializable so persistent storage can round-trip it.
type Session struct {
	*openid.DefaultSession `json:"oidc"`

	// FamilyIssuedAt is when the grant that started this token family was
	// first exchanged for tokens. Refresh rotation never extends past
	// FamilyIssuedAt + Tokens.RefreshTokenAbsoluteLifetime.
	FamilyIssuedAt time.Time `json:"family_issued_at,omitzero"`
}

var _ openid.Session = (*Session)(nil)

// Clone implements fosite.Session.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}
	c := &Session{FamilyIssuedAt: s.FamilyIssuedAt}
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
	if sub := sess.GetSubject(); sub != "" {
		return sub
	}
	if os, ok := sess.(openid.Session); ok && os.IDTokenClaims() != nil {
		return os.IDTokenClaims().Subject
	}
	return ""
}
