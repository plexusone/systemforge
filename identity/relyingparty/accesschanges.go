package relyingparty

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/clientcredentials"
)

// AccessChangeSource reads the access changes SystemAuth recorded after a
// time. The poller and Replay read through it: from the shared database
// (pgstore.NewAccessChangeSource, accesschange.NewSource) or from
// SystemAuth's GET /access-changes endpoint (Client.AccessChangesSource).
// It returns every change after since, oldest first, however many pages
// that takes.
type AccessChangeSource interface {
	AccessChangesSince(ctx context.Context, since time.Time) ([]AccessChange, error)
}

// Polling bounds (ADR-010 decision 4: every second or two).
const (
	// MinPollInterval and MaxPollInterval bound the polling interval.
	MinPollInterval = time.Second
	MaxPollInterval = 2 * time.Second
)

// suspectClearer is implemented by sinks that can be in suspect mode.
type suspectClearer interface{ ClearSuspect() }

// AccessChangePoller feeds a sink with the changes a source reports newer
// than its last read, so replicas that share a database but not memory
// see each other's access changes within one polling interval. One indexed
// query per instance per interval, independent of request volume.
//
// Each poll re-reads from the margin before the newest change it has seen,
// so a row that committed late with an earlier timestamp is still picked up;
// recording a change twice is harmless. The first successful poll reads back
// one maximum token lifetime plus the margin, as Replay does, and clears
// suspect mode on a sink that has one.
type AccessChangePoller struct {
	src      AccessChangeSource
	sink     AccessChangeSink
	interval time.Duration
	margin   time.Duration
	maxLife  time.Duration
	now      func() time.Time
	logger   *slog.Logger

	last   time.Time
	primed bool
}

// PollerOption configures an AccessChangePoller.
type PollerOption func(*AccessChangePoller)

// WithPollInterval sets the polling interval, limited to
// [MinPollInterval, MaxPollInterval]. The default is MinPollInterval.
func WithPollInterval(d time.Duration) PollerOption {
	return func(p *AccessChangePoller) { p.interval = min(max(d, MinPollInterval), MaxPollInterval) }
}

// WithPollerMargin sets the margin the poller re-reads behind the newest
// change. Use the sink cache's margin (the default is DefaultSkewMargin).
func WithPollerMargin(d time.Duration) PollerOption {
	return func(p *AccessChangePoller) { p.margin = max(d, MinSkewMargin) }
}

// WithPollerClock sets the poller's clock. For tests.
func WithPollerClock(now func() time.Time) PollerOption {
	return func(p *AccessChangePoller) { p.now = now }
}

// WithPollerLogger sets the logger that records failed polls.
func WithPollerLogger(l *slog.Logger) PollerOption {
	return func(p *AccessChangePoller) { p.logger = l }
}

// NewAccessChangePoller returns a poller reading src into sink.
func NewAccessChangePoller(src AccessChangeSource, sink AccessChangeSink, opts ...PollerOption) *AccessChangePoller {
	p := &AccessChangePoller{
		src: src, sink: sink,
		interval: MinPollInterval, margin: DefaultSkewMargin, maxLife: DefaultMaxTokenLifetime,
		now: time.Now, logger: slog.Default(),
	}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Poll reads the changes since the last read once. The first call reads
// back one maximum token lifetime plus the margin.
func (p *AccessChangePoller) Poll(ctx context.Context) error {
	started := p.now()
	since := p.last
	if !p.primed {
		since = started.Add(-p.maxLife - p.margin)
	}
	changes, err := p.src.AccessChangesSince(ctx, since)
	if err != nil {
		return fmt.Errorf("relyingparty: polling access changes: %w", err)
	}
	newest := since
	for _, c := range changes {
		p.sink.Record(c)
		if c.ChangedAt.After(newest) {
			newest = c.ChangedAt
		}
	}
	// Everything older than the margin is assumed committed and seen; keep
	// the margin before the newest change in case a row committed late.
	advance := started.Add(-p.margin)
	if n := newest.Add(-p.margin); n.After(advance) {
		advance = n
	}
	if advance.After(p.last) {
		p.last = advance
	}
	if !p.primed {
		p.primed = true
		if sc, ok := p.sink.(suspectClearer); ok {
			sc.ClearSuspect()
		}
	}
	return nil
}

// Run polls every interval until ctx is done. A failed poll is logged and
// retried at the next tick; until the first succeeds, a sink in suspect
// mode stays suspect. It returns ctx's error.
func (p *AccessChangePoller) Run(ctx context.Context) error {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		if err := p.Poll(ctx); err != nil && ctx.Err() == nil {
			p.logger.WarnContext(ctx, "polling access changes failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

// Replay rebuilds a cache after a restart: it reads the changes of the last
// maximum token lifetime plus the margin from src into cache and, once that
// has succeeded, ends the cache's suspect mode. Call it before serving
// (ADR-010 decision 6); until it returns, a cache marked with MarkSuspect
// refuses every token issued before it was marked.
func Replay(ctx context.Context, src AccessChangeSource, cache *RevocationCache) error {
	since := cache.now().Add(-cache.maxLife - cache.margin)
	changes, err := src.AccessChangesSince(ctx, since)
	if err != nil {
		return fmt.Errorf("relyingparty: replaying access changes: %w", err)
	}
	for _, c := range changes {
		cache.Record(c)
	}
	cache.ClearSuspect()
	return nil
}

// ReplayWithRetry calls Replay until it succeeds, waiting between
// attempts with exponential backoff from one second to thirty, logging each
// failure. The cache stays in suspect mode meanwhile, so the server may
// start serving at once and loses nothing but convenience. It returns nil
// after a success, or ctx's error.
func ReplayWithRetry(ctx context.Context, src AccessChangeSource, cache *RevocationCache, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	wait := time.Second
	for {
		err := Replay(ctx, src, cache)
		if err == nil {
			return nil
		}
		logger.WarnContext(ctx, "replaying access changes failed; staying in suspect mode", "error", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, 30*time.Second)
	}
}

// AccessChangesPath is the path of SystemAuth's replay endpoint.
const AccessChangesPath = "/access-changes"

// AccessChangesScope is the scope a client-credentials token needs to read
// the replay endpoint.
const AccessChangesScope = "access_changes:read"

// accessChangesPage is the replay endpoint's response.
type accessChangesPage struct {
	Changes []struct {
		PrincipalID    string    `json:"principal_id"`
		OrganizationID string    `json:"organization_id,omitempty"`
		ChangedAt      time.Time `json:"changed_at"`
		Reason         string    `json:"reason"`
	} `json:"changes"`
	// NextSince is set when more changes follow; pass it as since.
	NextSince *time.Time `json:"next_since,omitempty"`
}

type remoteAccessChanges struct {
	endpoint string
	token    func(ctx context.Context) (string, error)
	http     *http.Client
}

// AccessChangesSource reads changes from SystemAuth's GET /access-changes
// endpoint (replay), authenticating each request with the token token
// returns, which must carry AccessChangesScope. Use ClientCredentialsToken
// for a token source.
func (c *Client) AccessChangesSource(token func(ctx context.Context) (string, error)) AccessChangeSource {
	return &remoteAccessChanges{
		endpoint: strings.TrimRight(c.cfg.Issuer, "/") + AccessChangesPath,
		token:    token, http: c.cfg.HTTPClient,
	}
}

// ClientCredentialsToken returns a token source for the client-credentials
// grant with scope AccessChangesScope, for AccessChangesSource. The OAuth
// client must be registered with that scope and grant.
func (c *Client) ClientCredentialsToken(clientID, clientSecret string) func(ctx context.Context) (string, error) {
	cfg := clientcredentials.Config{
		ClientID: clientID, ClientSecret: clientSecret,
		TokenURL: c.metadata.TokenEndpoint, Scopes: []string{AccessChangesScope},
	}
	ts := cfg.TokenSource(c.httpContext(context.Background()))
	return func(context.Context) (string, error) {
		tok, err := ts.Token()
		if err != nil {
			return "", fmt.Errorf("relyingparty: access-changes token: %w", err)
		}
		return tok.AccessToken, nil
	}
}

// AccessChangesSince implements AccessChangeSource, following next_since.
func (r *remoteAccessChanges) AccessChangesSince(ctx context.Context, since time.Time) ([]AccessChange, error) {
	var out []AccessChange
	for range maxRemotePages {
		page, err := r.page(ctx, since)
		if err != nil {
			return nil, err
		}
		for _, c := range page.Changes {
			out = append(out, AccessChange{PrincipalID: c.PrincipalID, OrganizationID: c.OrganizationID, ChangedAt: c.ChangedAt, Reason: c.Reason})
		}
		if page.NextSince == nil {
			return out, nil
		}
		since = *page.NextSince
	}
	return nil, fmt.Errorf("relyingparty: access changes: more than %d pages", maxRemotePages)
}

func (r *remoteAccessChanges) page(ctx context.Context, since time.Time) (page *accessChangesPage, err error) {
	token, err := r.token(ctx)
	if err != nil {
		return nil, err
	}
	q := url.Values{"since": {since.UTC().Format(time.RFC3339Nano)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint+"?"+q.Encode(), http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relyingparty: access changes: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relyingparty: access changes: status %d (%s)", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize))
	if err != nil {
		return nil, fmt.Errorf("relyingparty: access changes: reading: %w", err)
	}
	page = &accessChangesPage{}
	if err := json.Unmarshal(body, page); err != nil {
		return nil, fmt.Errorf("relyingparty: access changes: decoding: %w", err)
	}
	return page, nil
}
