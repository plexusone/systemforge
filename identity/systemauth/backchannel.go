package systemauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
)

// Event identifiers carried in the "events" claim of a logout token.
const (
	// EventBackchannelLogout is the OpenID Connect Back-Channel Logout 1.0
	// event: the relying party ends the sessions of the token's sub (or
	// sid).
	EventBackchannelLogout = "http://schemas.openid.net/event/backchannel-logout"
	// EventAccessChange announces a reduction of the sub's access (ADR-010).
	// Its value holds organization_id (absent for every organization),
	// changed_at (RFC 3339) and reason.
	EventAccessChange = "urn:systemforge:event:access_change"
)

// LogoutTokenType is the JOSE typ header of a logout token.
const LogoutTokenType = "logout+jwt" //nolint:gosec // G101: a JOSE typ value, not a credential

// ErrInvalidBackchannelURI is returned for a back-channel logout URI that is
// not an acceptable delivery target.
var ErrInvalidBackchannelURI = errors.New("systemauth: invalid backchannel_logout_uri")

// ValidateBackchannelLogoutURI checks a client's back-channel endpoint. The
// empty string is valid and means none. SystemAuth POSTs to this address, so
// it must be an absolute https URL without credentials or a fragment; http
// is accepted only for loopback hosts, for development.
func ValidateBackchannelLogoutURI(raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("%w: %q must be an absolute URL without credentials or fragment", ErrInvalidBackchannelURI, raw)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
			return nil
		}
	}
	return fmt.Errorf("%w: %q must use https", ErrInvalidBackchannelURI, raw)
}

// Backchannel delivers access changes, and the logouts they imply, to the
// clients that registered a backchannel_logout_uri (ADR-010 decision 4,
// separate deployments). It is an accesschange.Sink: pass it to the
// WithAccessChangeSink option of the services that record changes, and run
// it with Run.
//
// Each change becomes one OpenID Connect Back-Channel Logout token per
// client, signed with the issuer key, typ logout+jwt, with sub, jti, iat and
// exp, aud set to the client ID and an "events" claim. The access_change
// event is always present; the back-channel logout event is added when the
// change ends the principal's sessions (deactivation, session revocation).
// It is POSTed as logout_token=<jwt>. A delivery that fails is retried with
// exponential backoff until one maximum access-token lifetime after the
// change, since after that no token issued before it can still be valid,
// and each failure is logged against the client ID. A response of 4xx other
// than 408 and 429 is permanent and not retried.
//
// A registered client receives the changes the server's AccessChangeScope
// (WithAccessChanges) allows it, and every change that names no
// organization. Without a scope, every registered client receives every
// change: the token carries only opaque principal and organization
// identifiers, but an operator who does not want a client to see other
// tenants' changes should configure a scope or not register an endpoint
// for it.
type Backchannel struct {
	s        *Server
	client   *http.Client
	logger   *slog.Logger
	queue    chan accesschange.Change
	base     time.Duration
	maxWait  time.Duration
	deadline time.Duration
	now      func() time.Time
	sem      chan struct{}
}

// BackchannelOption configures a Backchannel.
type BackchannelOption func(*Backchannel)

// WithBackchannelHTTPClient sets the HTTP client used for delivery. Its
// redirect policy is replaced so that a redirect is never followed.
func WithBackchannelHTTPClient(c *http.Client) BackchannelOption {
	return func(b *Backchannel) { b.client = c }
}

// WithBackchannelBackoff sets the first and the longest wait between
// attempts (1 second and 5 minutes by default).
func WithBackchannelBackoff(base, maxWait time.Duration) BackchannelOption {
	return func(b *Backchannel) { b.base, b.maxWait = base, maxWait }
}

// WithBackchannelClock sets the clock that stamps tokens and bounds
// retries. For tests.
func WithBackchannelClock(now func() time.Time) BackchannelOption {
	return func(b *Backchannel) { b.now = now }
}

const (
	backchannelQueueSize     = 1024
	backchannelMaxInFlight   = 64
	backchannelAttemptLimit  = 10 * time.Second
	backchannelTokenLifetime = 2 * time.Minute
)

// NewBackchannel returns a sender for s's clients and signing key.
func (s *Server) NewBackchannel(opts ...BackchannelOption) *Backchannel {
	b := &Backchannel{
		s:      s,
		client: &http.Client{Timeout: backchannelAttemptLimit},
		logger: s.logger,
		queue:  make(chan accesschange.Change, backchannelQueueSize),
		base:   time.Second, maxWait: 5 * time.Minute,
		deadline: accesschange.MaxAccessTokenLifetime,
		now:      time.Now,
		sem:      make(chan struct{}, backchannelMaxInFlight),
	}
	for _, o := range opts {
		o(b)
	}
	if b.logger == nil {
		b.logger = slog.Default()
	}
	// A redirect would let a client point SystemAuth at an address it did
	// not register.
	c := *b.client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b.client = &c
	return b
}

// AccessChange implements accesschange.Sink. It queues the change without
// blocking; a full queue drops it with a log line, which leaves the token
// lifetime as the bound for the affected clients.
func (b *Backchannel) AccessChange(c accesschange.Change) {
	select {
	case b.queue <- c:
	default:
		b.logger.Error("back-channel queue full; access change not delivered",
			"principal_id", c.PrincipalID, "reason", string(c.Reason))
	}
}

// Run delivers queued changes until ctx is done, then waits for deliveries
// in flight (they stop retrying at once). It returns ctx's error.
func (b *Backchannel) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case c := <-b.queue:
			clients, err := b.s.storage.ListClients(ctx)
			if err != nil {
				b.logger.ErrorContext(ctx, "back-channel: listing clients", "error", err)
				continue
			}
			for _, cl := range clients {
				if cl.BackchannelLogoutURI == "" {
					continue
				}
				if !b.inScope(ctx, cl.ID, c) {
					continue
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					b.deliver(ctx, cl.ID, cl.BackchannelLogoutURI, c)
				}()
			}
		}
	}
}

// inScope reports whether client may receive c: always when the server has
// no AccessChangeScope (WithAccessChanges) or c names no organization,
// otherwise when the scope includes c's organization. A scope that fails
// is logged and the change is not delivered to that client; the token
// lifetime bounds what it misses.
func (b *Backchannel) inScope(ctx context.Context, clientID string, c accesschange.Change) bool {
	if b.s.accessScope == nil || c.OrganizationID == nil {
		return true
	}
	orgIDs, all, err := b.s.accessScope(ctx, clientID)
	if err != nil {
		b.logger.ErrorContext(ctx, "back-channel: resolving the client's organizations", "client_id", clientID, "error", err)
		return false
	}
	return all || slices.Contains(orgIDs, *c.OrganizationID)
}

// deliver sends one change to one client, retrying until it is accepted,
// refused for good, past its deadline or ctx is done.
func (b *Backchannel) deliver(ctx context.Context, clientID, endpoint string, c accesschange.Change) {
	wait := b.base
	for attempt := 1; ; attempt++ {
		permanent, err := b.attempt(ctx, clientID, endpoint, c)
		if err == nil {
			return
		}
		b.logger.WarnContext(ctx, "back-channel delivery failed",
			"client_id", clientID, "attempt", attempt, "principal_id", c.PrincipalID,
			"reason", string(c.Reason), "permanent", permanent, "error", err)
		if permanent {
			return
		}
		// Jitter keeps clients that failed together from retrying together.
		//nolint:gosec // G404: jitter for retry spacing needs no cryptographic randomness
		sleep := wait/2 + time.Duration(rand.Int64N(int64(wait/2)+1))
		if b.now().Add(sleep).After(c.ChangedAt.Add(b.deadline)) {
			b.logger.ErrorContext(ctx, "back-channel delivery abandoned: past one access-token lifetime",
				"client_id", clientID, "principal_id", c.PrincipalID, "reason", string(c.Reason))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(sleep):
		}
		wait = min(wait*2, b.maxWait)
	}
}

// attempt makes one delivery. permanent reports a refusal that retrying
// cannot fix.
func (b *Backchannel) attempt(ctx context.Context, clientID, endpoint string, c accesschange.Change) (permanent bool, err error) {
	select {
	case b.sem <- struct{}{}:
		defer func() { <-b.sem }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	token, err := b.logoutToken(clientID, c)
	if err != nil {
		return true, err
	}
	body := url.Values{"logout_token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		return false, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	// Drain a little so the connection can be reused; the body is ignored.
	if _, cerr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); cerr != nil {
		return false, cerr
	}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return false, nil
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}
	return true, fmt.Errorf("refused with status %d", resp.StatusCode)
}

// logoutToken builds and signs the logout token for client and change.
func (b *Backchannel) logoutToken(clientID string, c accesschange.Change) (string, error) {
	now := b.now()
	event := map[string]any{
		"changed_at": c.ChangedAt.UTC().Format(time.RFC3339Nano),
		"reason":     string(c.Reason),
	}
	if c.OrganizationID != nil {
		event["organization_id"] = c.OrganizationID.String()
	}
	events := map[string]any{EventAccessChange: event}
	switch c.Reason {
	case accesschange.Deactivated, accesschange.SessionsRevoked:
		events[EventBackchannelLogout] = map[string]any{}
	}
	tok := gojwt.NewWithClaims(gojwt.SigningMethodRS256, gojwt.MapClaims{
		"iss":    b.s.config.Issuer,
		"aud":    clientID,
		"sub":    c.PrincipalID.String(),
		"iat":    now.Unix(),
		"exp":    now.Add(backchannelTokenLifetime).Unix(),
		"jti":    uuid.NewString(),
		"events": events,
	})
	tok.Header["typ"] = LogoutTokenType
	tok.Header["kid"] = b.s.keyID
	signed, err := tok.SignedString(b.s.key)
	if err != nil {
		return "", fmt.Errorf("systemauth: signing logout token: %w", err)
	}
	return signed, nil
}

var _ accesschange.Sink = (*Backchannel)(nil)
