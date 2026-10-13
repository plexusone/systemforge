package systemauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/google/uuid"
)

// ErrSignupNotInvited is returned by a SignupGate that refuses to create an
// account for a login. The social login callback turns it into a denial
// page or a 403; it never says why, so a visitor cannot tell an address that
// has no invite from one whose invite expired.
var ErrSignupNotInvited = errors.New("systemauth: sign-up is by invitation only")

// SignupGate decides whether an upstream login may create a new account.
// It runs only when no principal exists for the login: a person who already
// has an account, or whose verified email links to one, signs in without
// consulting it.
type SignupGate interface {
	// AllowSignup returns nil to let the account be created and
	// ErrSignupNotInvited to refuse. Any other error also refuses the
	// login, as a server fault.
	AllowSignup(ctx context.Context, login ExternalLogin) error

	// SignedUp is called once the account exists, so the gate can consume
	// an invite. A failure is logged and does not undo the account.
	SignedUp(ctx context.Context, login ExternalLogin, principalID uuid.UUID) error
}

// WithSignupGate makes social login create accounts only for logins gate
// allows. Existing accounts are unaffected.
func WithSignupGate(gate SignupGate) Option {
	return func(s *Server) { s.socialOpts.signupGate = gate }
}

// WithSignupDeniedURL sets where a refused sign-up is sent. The browser is
// redirected there with error=invite_required in the query. Without it the
// callback answers 403. The URL must be absolute (https, or http for a
// loopback host).
func WithSignupDeniedURL(rawURL string) Option {
	return func(s *Server) { s.socialOpts.signupDeniedURL = rawURL }
}

// ValidateSignupDeniedURL reports whether raw is acceptable to
// WithSignupDeniedURL, so a host can refuse a bad value at startup rather
// than when social login is first built.
func ValidateSignupDeniedURL(raw string) error {
	_, err := parseSignupDeniedURL(raw)
	return err
}

// parseSignupDeniedURL validates the denial page address.
func parseSignupDeniedURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("signup denied URL: %w", err)
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	switch {
	case u.Host == "":
		return nil, errors.New("signup denied URL must be absolute")
	case u.Scheme != "https" && (u.Scheme != "http" || !loopback):
		return nil, errors.New("signup denied URL must be https (http only for a loopback host)")
	case u.User != nil:
		return nil, errors.New("signup denied URL must not carry credentials")
	}
	return u, nil
}

// gatedDirectory refuses to create accounts the gate does not allow and
// otherwise behaves as the directory it wraps.
type gatedDirectory struct {
	PrincipalDirectory
	gate   SignupGate
	logger *slog.Logger
}

// CreateFromExternal implements PrincipalDirectory.
func (d *gatedDirectory) CreateFromExternal(ctx context.Context, login ExternalLogin) (*HumanPrincipal, error) {
	if err := d.gate.AllowSignup(ctx, login); err != nil {
		return nil, err
	}
	p, err := d.PrincipalDirectory.CreateFromExternal(ctx, login)
	if err != nil {
		return nil, err
	}
	if err := d.gate.SignedUp(ctx, login, p.ID); err != nil {
		d.logger.WarnContext(ctx, "recording a sign-up against its invite failed", "principal_id", p.ID, "error", err)
	}
	return p, nil
}

// EnsurePersonalOrg implements PersonalOrgEnsurer by delegating when the
// wrapped directory keeps personal organizations.
func (d *gatedDirectory) EnsurePersonalOrg(ctx context.Context, p *HumanPrincipal, login ExternalLogin) error {
	if e, ok := d.PrincipalDirectory.(PersonalOrgEnsurer); ok {
		return e.EnsurePersonalOrg(ctx, p, login)
	}
	return nil
}
