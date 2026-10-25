package systemauthsvc

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/signupgate"
	"github.com/plexusone/systemforge/identity/signupgate/signupapi"
)

// SignupAPIPath is where Options.SignupAPI serves the invite API on the
// SystemAuth host.
const SignupAPIPath = "/signup-invites/api"

// errNoSignupSession is returned to the invite API for a request without a
// SystemAuth login session.
var errNoSignupSession = errors.New("systemauthsvc: no login session")

// SignupCodes returns the store of invite codes, their redemptions and
// member allowances over the service's database, with the member invite
// settings from Options.MemberInvites, or nil without a database. Codes only
// admit people when Options.SignupCodes is set.
func (s *Service) SignupCodes() *signupgate.CodeStore {
	if s.client == nil {
		return nil
	}
	return signupgate.NewCodeStore(s.client, s.member)
}

// SignupAPI returns the invite API (signupapi) over the service's database
// for a host that serves it behind its own session: principal returns the
// person signed in to the host. Operator routes are for platform
// administrators. Mount it under a prefix with http.StripPrefix. It needs a
// database.
func (s *Service) SignupAPI(principal func(*http.Request) (uuid.UUID, error)) (http.Handler, error) {
	if s.client == nil {
		return nil, errors.New("systemauthsvc: the invite API needs a database")
	}
	h, err := signupapi.New(signupapi.Options{
		Invites:   s.SignupInvites(),
		Codes:     s.SignupCodes(),
		Waitlist:  s.SignupWaitlist(),
		Principal: principal,
		IsAdmin:   s.isPlatformAdmin,
		SignupURL: s.signupURL,
		Audit:     s.audit,
		Logger:    s.logger,
	})
	if err != nil {
		return nil, fmt.Errorf("systemauthsvc: %w", err)
	}
	return h, nil
}

// mountSignupAPI serves the invite API at SignupAPIPath for the person
// signed in with the SystemAuth login session.
func (s *Service) mountSignupAPI() error {
	h, err := s.SignupAPI(func(r *http.Request) (uuid.UUID, error) {
		sess, err := s.server.CurrentLoginSession(r)
		if err != nil {
			return uuid.Nil, errors.Join(errNoSignupSession, err)
		}
		return sess.PrincipalID, nil
	})
	if err != nil {
		return err
	}
	router := s.server.Router()
	router.Mount(SignupAPIPath, http.StripPrefix(SignupAPIPath, h))
	s.logger.Info("invite API enabled", "path", SignupAPIPath)
	return nil
}
