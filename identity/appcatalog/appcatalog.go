// Package appcatalog describes the applications a SystemForge deployment
// hosts, for the product switcher every application's shell shows: each
// application's name, where it opens, its icon and its place in the list.
//
// An application's identifier is the one its authz.AppVocabulary declares
// and its entitlements and the orgs claim's apps map use, so registering an
// application is one step: roles and scopes in the vocabulary, how it is
// shown here. SystemAuth publishes the catalog at WellKnownPath; it is
// public, since names and launch URLs are not secret. Which entries a person
// sees is decided per organization by the orgs claim: an application they
// hold no role in is not shown.
package appcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// WellKnownPath is where SystemAuth publishes the catalog.
const WellKnownPath = "/.well-known/sf-apps"

// App is one application in the catalog.
type App struct {
	// ID is the application identifier, as its vocabulary declares it.
	ID string `json:"id"`
	// Name is what the switcher shows.
	Name string `json:"name"`
	// URL is where the application opens: an absolute https URL (http only
	// for a loopback host).
	URL string `json:"url"`
	// Icon is an optional icon URL or short icon name the shells know.
	Icon string `json:"icon,omitempty"`
	// Order places the application in the list, lowest first; ties are
	// ordered by name.
	Order int `json:"order,omitempty"`
}

// Document is the published catalog.
type Document struct {
	Apps []App `json:"apps"`
}

// Catalog is a validated, ordered set of applications.
type Catalog struct {
	apps []App
}

var idRe = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

// New validates apps and returns their catalog. Identifiers must be unique
// short lower-case names (the vocabulary rule), names non-empty, and URLs
// absolute https (http only for a loopback host) without credentials.
func New(apps ...App) (*Catalog, error) {
	seen := map[string]bool{}
	var errs []error
	out := make([]App, 0, len(apps))
	for _, a := range apps {
		a.Name = strings.TrimSpace(a.Name)
		switch {
		case !idRe.MatchString(a.ID):
			errs = append(errs, fmt.Errorf("appcatalog: invalid application id %q", a.ID))
			continue
		case seen[a.ID]:
			errs = append(errs, fmt.Errorf("appcatalog: application %q listed twice", a.ID))
			continue
		case a.Name == "":
			errs = append(errs, fmt.Errorf("appcatalog: application %q has no name", a.ID))
		}
		if err := checkURL(a.URL); err != nil {
			errs = append(errs, fmt.Errorf("appcatalog: application %q: %w", a.ID, err))
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].Name < out[j].Name
	})
	return &Catalog{apps: out}, nil
}

func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	host := u.Hostname()
	loopback := host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "127.0.0.1" || host == "::1"
	switch {
	case u.Host == "":
		return errors.New("url must be absolute")
	case u.User != nil:
		return errors.New("url must not carry credentials")
	case u.Scheme != "https" && (u.Scheme != "http" || !loopback):
		return errors.New("url must be https (http only for a loopback host)")
	}
	return nil
}

// Apps returns the applications in order. The slice is a copy.
func (c *Catalog) Apps() []App {
	if c == nil {
		return []App{}
	}
	return slices.Clone(c.apps)
}

// Get returns the application with id.
func (c *Catalog) Get(id string) (App, bool) {
	if c == nil {
		return App{}, false
	}
	for _, a := range c.apps {
		if a.ID == id {
			return a, true
		}
	}
	return App{}, false
}

// Document returns the catalog as published.
func (c *Catalog) Document() Document { return Document{Apps: c.Apps()} }

// Source supplies the catalog to a relying party.
type Source interface {
	Apps(ctx context.Context) ([]App, error)
}

// Static serves a catalog the host already has (an application embedded
// with SystemAuth in one process).
func Static(c *Catalog) Source { return staticSource{c} }

type staticSource struct{ c *Catalog }

func (s staticSource) Apps(context.Context) ([]App, error) { return s.c.Apps(), nil }

// DefaultCacheTTL is how long Remote reuses a fetched catalog.
const DefaultCacheTTL = 5 * time.Minute

// maxDocumentSize bounds the published catalog Remote reads.
const maxDocumentSize = 1 << 20

// Remote fetches the catalog SystemAuth publishes at issuer +
// WellKnownPath and reuses it for ttl (DefaultCacheTTL when zero). A failed
// fetch returns the last catalog it fetched, if any, so a SystemAuth outage
// does not empty the switcher.
func Remote(issuer string, client *http.Client, ttl time.Duration) Source {
	if client == nil {
		client = http.DefaultClient
	}
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &remoteSource{endpoint: strings.TrimRight(issuer, "/") + WellKnownPath, client: client, ttl: ttl, now: time.Now}
}

type remoteSource struct {
	endpoint string
	client   *http.Client
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	apps    []App
	fetched time.Time
	have    bool
}

func (r *remoteSource) Apps(ctx context.Context) ([]App, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.have && r.now().Sub(r.fetched) < r.ttl {
		return slices.Clone(r.apps), nil
	}
	apps, err := r.fetch(ctx)
	if err != nil {
		if r.have {
			return slices.Clone(r.apps), nil
		}
		return nil, err
	}
	r.apps, r.fetched, r.have = apps, r.now(), true
	return slices.Clone(apps), nil
}

func (r *remoteSource) fetch(ctx context.Context) (apps []App, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("appcatalog: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("appcatalog: fetching the catalog: %w", err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("appcatalog: closing the response: %w", cerr)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("appcatalog: fetching the catalog: status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentSize))
	if err != nil {
		return nil, fmt.Errorf("appcatalog: reading the catalog: %w", err)
	}
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("appcatalog: decoding the catalog: %w", err)
	}
	c, err := New(doc.Apps...)
	if err != nil {
		return nil, err
	}
	return c.Apps(), nil
}
