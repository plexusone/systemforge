package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
)

// Security event types SystemAuth emits through the audit emitter set with
// WithAuditEmitter. docs/security/security-events.md describes each one's
// fields.
const (
	EventSignIn                 = "systemauth.sign_in"
	EventSignOut                = "systemauth.sign_out"
	EventTokenRefused           = "systemauth.token.refused"
	EventRefreshTokenReuse      = "systemauth.refresh_token.reuse" //nolint:gosec // G101: an event name, not a credential
	EventAuthorizationCodeReuse = "systemauth.authorization_code.reuse"
	EventTokenRevoked           = "systemauth.token.revoked"
	EventTokenFamilyRevoked     = "systemauth.token_family.revoked"
	EventSigningKeyLoaded       = "systemauth.signing_key.loaded"
)

// Actor types of SystemAuth's security events.
const (
	actorPrincipal   = "principal"
	actorApplication = "application"
	actorService     = "service"
)

// WithAuditEmitter sets where the server records security events: sign-ins
// and their refusals, sign-outs, refused token requests, refresh-token
// reuse and authorization-code replay, revocations, and the signing key in
// use at startup. Each event carries the request ID, the principal and
// client IDs and the client address, and never a token, code or secret.
// Default: events are discarded. audit.NewLogEmitter writes them to a log.
func WithAuditEmitter(e audit.Emitter) Option {
	return func(s *Server) {
		if e == nil {
			e = audit.NopEmitter{}
		}
		s.audit = e
	}
}

// eventRequest is what a security event records of the request that
// caused it.
type eventRequest struct {
	clientIP  string
	userAgent string
}

type eventRequestKey struct{}

// eventRequestMiddleware keeps the request's client address and user agent
// in its context, so code without the request, such as a token-family
// revocation, can still record them.
// The address comes from the server's client-address rule, the same one rate
// limits use, so events behind a reverse proxy record the visitor, not the
// proxy.
func (s *Server) eventRequestMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), eventRequestKey{}, eventRequest{
			clientIP:  s.clientIP(r),
			userAgent: r.UserAgent(),
		})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// emitEvent fills ev's time and request context and records it. An event is
// recorded after the outcome it describes, so a failure to record it is
// logged rather than returned.
func (s *Server) emitEvent(ctx context.Context, ev *audit.Event) {
	if s.audit == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Outcome == "" {
		ev.Outcome = audit.OutcomeSuccess
	}
	ev.Context.RequestID = audit.RequestID(ctx)
	if req, ok := ctx.Value(eventRequestKey{}).(eventRequest); ok {
		ev.Context.ClientIP = req.clientIP
		ev.Context.UserAgent = req.userAgent
	}
	if err := s.audit.Emit(ctx, ev); err != nil {
		s.logger.ErrorContext(ctx, "recording security event", "event_type", ev.EventType, "error", err.Error())
	}
}

// tokenRefused records a refused token request. reason is SystemAuth's own
// short code for the check that refused it; err is the OAuth error the
// client received.
func (s *Server) tokenRefused(ctx context.Context, r *http.Request, grantType, clientID, reason string, err error) {
	if clientID == "" {
		clientID = requestClientID(r)
	}
	s.emitEvent(ctx, &audit.Event{
		EventType: EventTokenRefused,
		Action:    "issue_token",
		Actor:     clientActor(clientID),
		Resource:  audit.Resource{Type: "token"},
		Outcome:   audit.OutcomeFailure,
		Details:   details("grant_type", grantType, "client_id", clientID, "reason", reason, "error", oauthcore.ErrorCode(err)),
	})
}

// codeReusedHint is the hint of the error refusing an authorization code
// that was already exchanged, Fosite's and SystemAuth's own.
const codeReusedHint = "The authorization code has already been used."

// tokenRequestFailed records a token request Fosite refused, and the
// replay it detected: a reused refresh token, or a reused authorization
// code. Fosite revokes the tokens issued from either before refusing it.
func (s *Server) tokenRequestFailed(ctx context.Context, r *http.Request, grantType string, err error) {
	clientID := requestClientID(r)
	switch {
	case grantType == "refresh_token" && errors.Is(err, fosite.ErrInactiveToken):
		s.emitEvent(ctx, &audit.Event{
			EventType: EventRefreshTokenReuse,
			Action:    "redeem_refresh_token",
			Actor:     clientActor(clientID),
			Resource:  audit.Resource{Type: "token_family"},
			Outcome:   audit.OutcomeFailure,
			Details:   details("grant_type", grantType, "client_id", clientID, "family_revoked", true),
		})
	case grantType == "authorization_code" && strings.HasPrefix(fosite.ErrorToRFC6749Error(err).HintField, codeReusedHint):
		s.codeReused(ctx, grantType, clientID, true)
	}
	s.tokenRefused(ctx, r, grantType, clientID, "request_invalid", err)
}

// codeReused records a second exchange of an authorization code.
// familyRevoked tells whether the tokens the first exchange issued were
// revoked.
func (s *Server) codeReused(ctx context.Context, grantType, clientID string, familyRevoked bool) {
	s.emitEvent(ctx, &audit.Event{
		EventType: EventAuthorizationCodeReuse,
		Action:    "redeem_authorization_code",
		Actor:     clientActor(clientID),
		Resource:  audit.Resource{Type: "authorization_code"},
		Outcome:   audit.OutcomeFailure,
		Details:   details("grant_type", grantType, "client_id", clientID, "family_revoked", familyRevoked),
	})
}

// tokenRevoked records a request to the revocation endpoint. The token
// itself is never recorded; its type hint is.
func (s *Server) tokenRevoked(ctx context.Context, r *http.Request, err error) {
	clientID := requestClientID(r)
	ev := &audit.Event{
		EventType: EventTokenRevoked,
		Action:    "revoke",
		Actor:     clientActor(clientID),
		Resource:  audit.Resource{Type: "token"},
		Details:   details("client_id", clientID, "token_type_hint", tokenTypeHint(r)),
	}
	if err != nil {
		ev.Outcome = audit.OutcomeFailure
		ev.Details["error"] = oauthcore.ErrorCode(err)
	}
	s.emitEvent(ctx, ev)
}

// tokenTypeHint returns the request's token_type_hint when it is one of
// the values RFC 7009 defines, so a client cannot put arbitrary text into
// the event.
func tokenTypeHint(r *http.Request) string {
	if r == nil || r.PostForm == nil {
		return ""
	}
	switch h := r.PostForm.Get("token_type_hint"); h {
	case "access_token", "refresh_token":
		return h
	}
	return ""
}

// tokenFamilyRevoked records the revocation of the token family that
// began with the authorization request requestID.
func (s *Server) tokenFamilyRevoked(ctx context.Context, requestID, subject, clientID, reason string) {
	s.emitEvent(ctx, &audit.Event{
		EventType: EventTokenFamilyRevoked,
		Action:    "revoke",
		Actor:     audit.Actor{Type: actorService, Identifier: "systemauth"},
		Resource:  audit.Resource{Type: "token_family", Identifier: requestID},
		Details:   details("reason", reason, "subject", subject, "client_id", clientID),
	})
}

// signingKeyLoaded records, at startup, the key the server signs with and
// the keys it still verifies with: a rotation shows as a new signing kid
// with the previous one among the verification kids.
func (s *Server) signingKeyLoaded(ephemeral bool) {
	kids := make([]string, 0, len(s.config.Keys.VerificationKeys))
	for _, v := range s.config.Keys.VerificationKeys {
		kids = append(kids, v.KeyID)
	}
	s.emitEvent(context.Background(), &audit.Event{
		EventType: EventSigningKeyLoaded,
		Action:    "load",
		Actor:     audit.Actor{Type: actorService, Identifier: "systemauth"},
		Resource:  audit.Resource{Type: "signing_key", Identifier: s.keyID},
		Details:   details("key_id", s.keyID, "verification_key_ids", kids, "ephemeral", ephemeral),
	})
}

// requesterClientID returns the ID of the client of ar, or "" when it has
// none.
func requesterClientID(ar fosite.Requester) string {
	if c := ar.GetClient(); c != nil {
		return c.GetID()
	}
	return ""
}

// requestClientID returns the client ID a token request names, in its
// form or its basic-auth user name, for requests refused before the client
// was authenticated. It is the client's claim, not a verified identity.
func requestClientID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if user, _, ok := r.BasicAuth(); ok && user != "" {
		if id, err := url.QueryUnescape(user); err == nil {
			return id
		}
		return user
	}
	if r.PostForm != nil {
		return r.PostForm.Get("client_id")
	}
	return ""
}

// clientActor names an OAuth client as an event's actor.
func clientActor(clientID string) audit.Actor {
	return audit.Actor{Type: actorApplication, Identifier: clientID}
}

// details builds an event's details from key/value pairs, leaving out empty
// strings.
func details(kv ...any) map[string]any {
	out := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		if v, isString := kv[i+1].(string); isString && v == "" {
			continue
		}
		out[k] = kv[i+1]
	}
	return out
}
