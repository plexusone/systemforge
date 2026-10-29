package systemauth

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
)

// signedIn records a sign-in that created a login session. method is the
// social provider, or "login_token"; clientID is the client a login token
// was exchanged through.
func (sl *socialLogin) signedIn(ctx context.Context, principalID uuid.UUID, method, clientID string) {
	sl.emit(ctx, &audit.Event{
		EventType: EventSignIn,
		Action:    "sign_in",
		Actor:     audit.Actor{ID: principalID, Type: actorPrincipal},
		Resource:  audit.Resource{Type: "login_session"},
		Details:   details("method", method, "client_id", clientID),
	})
}

// signInRefused records a refused sign-in with SystemAuth's reason code.
func (sl *socialLogin) signInRefused(ctx context.Context, method, clientID, reason string) {
	sl.emit(ctx, &audit.Event{
		EventType: EventSignIn,
		Action:    "sign_in",
		Actor:     audit.Actor{Type: actorPrincipal},
		Resource:  audit.Resource{Type: "login_session"},
		Outcome:   audit.OutcomeFailure,
		Details:   details("method", method, "client_id", clientID, "reason", reason),
	})
}

// signedOut records the end of a login session and the revocation of the
// principal's tokens that comes with it.
func (sl *socialLogin) signedOut(ctx context.Context, sess LoginSession) {
	sl.emit(ctx, &audit.Event{
		EventType: EventSignOut,
		Action:    "sign_out",
		Actor:     audit.Actor{ID: sess.PrincipalID, Type: actorPrincipal},
		Resource:  audit.Resource{Type: "login_session"},
		Details:   details("method", sess.Provider, "tokens_revoked", sl.revoker != nil),
	})
}

// signInRefusalReason maps an error resolving an external login to the
// reason code of the refused sign-in, or "" when the sign-in is not
// refused but continues with the sign-up age question.
func signInRefusalReason(err error) string {
	switch {
	case errors.Is(err, errSignupAgeRequired):
		return ""
	case errors.Is(err, ErrEmailNotVerified):
		return "email_not_verified"
	case errors.Is(err, ErrEmailConflict):
		return "email_conflict"
	case errors.Is(err, ErrPrincipalInactive):
		return "principal_inactive"
	case errors.Is(err, ErrSignupNotInvited):
		return "not_invited"
	}
	return "server_error"
}
