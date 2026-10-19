// Package console serves the organization console (ADR-018): organization
// administration on the SystemAuth host, signed in with the SystemAuth login
// session. It mounts existing handlers, such as the connections API, under
// /console/api with a session authenticator, and serves the console's built
// pages under /console/.
//
// The console delegates nothing, so OAuth scopes do not apply to it; every
// request is authorized by the person's organization role and grants, as any
// caller's is. State-changing requests must be same-origin.
package console

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/connections"
)

// Paths.
const (
	// Prefix is where the console is served.
	Prefix = "/console"
	// APIPrefix is the console's API.
	APIPrefix = Prefix + "/api"
	// SessionPath describes the signed-in person and their organizations.
	SessionPath = APIPrefix + "/v1/session"
	// ReturnToPath checks a return address from an application's link.
	ReturnToPath = APIPrefix + "/v1/return-to"
)

// ErrNoSession is returned by [Options.Principal] when the request carries
// no valid login session.
var ErrNoSession = errors.New("console: no login session")

// Organization is an organization the signed-in person belongs to.
type Organization struct {
	ID   string `json:"id"`
	Slug string `json:"slug,omitempty"`
	Name string `json:"name,omitempty"`
	// Type is personal, team or enterprise.
	Type string `json:"type,omitempty"`
	// Role is the person's organization role: owner, admin, member or
	// collaborator.
	Role string `json:"role"`
}

// Options configures a console.
type Options struct {
	// Principal returns the person signed in on r, or an error wrapping
	// ErrNoSession. Required.
	Principal func(r *http.Request) (uuid.UUID, error)
	// Organizations lists the person's organizations, personal first.
	// Required.
	Organizations func(ctx context.Context, principal uuid.UUID) ([]Organization, error)
	// ReturnTo validates a return address, returning the URL to use or an
	// error. Required.
	ReturnTo func(raw string) (string, error)
	// Connections, if set, serves the connections section.
	Connections *connections.Connections
	// WebDir holds the built console pages. Empty serves only the API.
	WebDir string
	// LoginPath is where a page load without a session is sent, with the
	// page as return_to. Default "/login".
	LoginPath string
	Logger    *slog.Logger
}

// Console is the organization console's handler.
type Console struct {
	h http.Handler
}

// New returns a console for o.
func New(o Options) (*Console, error) {
	if o.Principal == nil || o.Organizations == nil || o.ReturnTo == nil {
		return nil, errors.New("console: Principal, Organizations and ReturnTo are required")
	}
	if o.LoginPath == "" {
		o.LoginPath = "/login"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	c := &console{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+SessionPath, c.session)
	mux.HandleFunc("GET "+ReturnToPath, c.returnTo)
	if o.Connections != nil {
		h := http.StripPrefix(Prefix, o.Connections.Handler(c.authenticate, c.writeAuthError, o.Logger))
		mux.Handle(Prefix+connections.ProvidersPath, h)
		mux.Handle(Prefix+connections.ConnectionsPath, h)
		mux.Handle(Prefix+connections.ConnectionsPath+"/", h)
	}
	mux.HandleFunc(APIPrefix+"/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	if o.WebDir != "" {
		root, err := os.OpenRoot(o.WebDir)
		if err != nil {
			return nil, fmt.Errorf("console: web directory: %w", err)
		}
		if _, err := root.Stat("index.html"); err != nil {
			return nil, fmt.Errorf("console: web directory has no index.html: %w", err)
		}
		c.pages = root
		// Not "GET /console/": a method-specific pattern would conflict with
		// the API's fallback, which is more specific by path.
		mux.HandleFunc(Prefix+"/", c.page)
		mux.Handle(Prefix, http.RedirectHandler(Prefix+"/", http.StatusMovedPermanently))
	}
	return &Console{h: headers(http.NewCrossOriginProtection().Handler(mux))}, nil
}

// ServeHTTP implements [http.Handler].
func (c *Console) ServeHTTP(w http.ResponseWriter, r *http.Request) { c.h.ServeHTTP(w, r) }

type console struct {
	o     Options
	pages *os.Root
}

// authenticate is the connections API's authenticator. It ignores the scope:
// the console acts as the signed-in person and delegates nothing (ADR-018).
func (c *console) authenticate(r *http.Request, _ string) (uuid.UUID, error) {
	return c.o.Principal(r)
}

func (c *console) writeAuthError(w http.ResponseWriter, err error, _ string) {
	if errors.Is(err, ErrNoSession) {
		writeError(w, http.StatusUnauthorized, "sign in required")
		return
	}
	c.o.Logger.Error("console: reading the login session", "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

type sessionResponse struct {
	Principal     sessionPrincipal `json:"principal"`
	Organizations []Organization   `json:"organizations"`
	Sections      sections         `json:"sections"`
}

type sessionPrincipal struct {
	ID string `json:"id"`
}

type sections struct {
	Connections bool `json:"connections"`
}

func (c *console) session(w http.ResponseWriter, r *http.Request) {
	pid, err := c.o.Principal(r)
	if err != nil {
		c.writeAuthError(w, err, "")
		return
	}
	orgs, err := c.o.Organizations(r.Context(), pid)
	if err != nil {
		c.o.Logger.Error("console: listing organizations", "principal", pid, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if orgs == nil {
		orgs = []Organization{}
	}
	writeJSON(w, http.StatusOK, sessionResponse{
		Principal:     sessionPrincipal{ID: pid.String()},
		Organizations: orgs,
		Sections:      sections{Connections: c.o.Connections != nil},
	})
}

// returnTo checks the return address an application's link carries, so the
// pages send a person back only where sign-in would.
func (c *console) returnTo(w http.ResponseWriter, r *http.Request) {
	if _, err := c.o.Principal(r); err != nil {
		c.writeAuthError(w, err, "")
		return
	}
	u, err := c.o.ReturnTo(r.URL.Query().Get("url"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "return address not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"url": u})
}

// page serves a built file, or index.html for a console route. A route
// without a session goes to sign-in and comes back.
func (c *console) page(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rel := strings.TrimPrefix(path.Clean(r.URL.Path), Prefix)
	rel = strings.TrimPrefix(rel, "/")
	if rel != "" && path.Ext(rel) != "" {
		c.file(w, r, rel)
		return
	}
	if _, err := c.o.Principal(r); err != nil {
		if !errors.Is(err, ErrNoSession) {
			c.writeAuthError(w, err, "")
			return
		}
		http.Redirect(w, r, c.o.LoginPath+"?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	c.serve(w, r, "index.html")
}

// file serves a built asset. Hashed assets under assets/ are immutable.
func (c *console) file(w http.ResponseWriter, r *http.Request, rel string) {
	if strings.HasPrefix(rel, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	c.serve(w, r, rel)
}

func (c *console) serve(w http.ResponseWriter, r *http.Request, rel string) {
	f, err := c.pages.Open(rel)
	if err != nil {
		// Missing files, and paths the root refuses (outside it, or through
		// a link that leaves it), are not found.
		if !errors.Is(err, fs.ErrNotExist) {
			c.o.Logger.Warn("console: refused a page", "path", rel, "error", err)
		}
		http.NotFound(w, r)
		return
	}
	defer func() {
		if err := f.Close(); err != nil {
			c.o.Logger.Error("console: closing a page", "path", rel, "error", err)
		}
	}()
	st, err := f.Stat()
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, st.Name(), st.ModTime(), f)
}

// contentSecurityPolicy allows the console's own scripts and styles, inline
// styles for component libraries, and images from data URLs.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// headers sets the console's security headers. API responses are never
// cached.
func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, APIPrefix+"/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is sent; the client sees a truncated body.
		slog.Default().Error("console: writing a response", "error", err)
	}
}
