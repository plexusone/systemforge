package requestprincipal_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// headerAuth accepts requests carrying its header with value "good".
type headerAuth struct {
	header, challenge string
	typ               requestprincipal.Type
}

func (a headerAuth) Authenticate(r *http.Request) (*requestprincipal.RequestPrincipal, error) {
	switch v := r.Header.Get(a.header); v {
	case "":
		return nil, fmt.Errorf("%s: %w", a.header, requestprincipal.ErrNoCredentials)
	case "good":
		return &requestprincipal.RequestPrincipal{PrincipalID: a.header, Type: a.typ, Scopes: []string{"read"}}, nil
	case "broken":
		return nil, errors.New("store unavailable")
	default:
		return nil, &requestprincipal.Error{Status: http.StatusForbidden, Code: "DENIED", Message: "bad " + a.header}
	}
}

func (a headerAuth) Challenge(h http.Header) { h.Add(a.header+"-Challenge", a.challenge) }

func serve(t *testing.T, opts requestprincipal.Options, headers map[string]string) (*httptest.ResponseRecorder, *requestprincipal.RequestPrincipal) {
	t.Helper()
	var got *requestprincipal.RequestPrincipal
	h := requestprincipal.Middleware(opts,
		headerAuth{header: "X-Agent", challenge: "agent", typ: requestprincipal.TypeAgent},
		headerAuth{header: "X-Human", challenge: "human", typ: requestprincipal.TypeHuman},
	)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = requestprincipal.FromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, got
}

func TestMiddleware(t *testing.T) {
	// Each authenticator serves its own credentials.
	for header, typ := range map[string]requestprincipal.Type{"X-Agent": requestprincipal.TypeAgent, "X-Human": requestprincipal.TypeHuman} {
		w, p := serve(t, requestprincipal.Options{}, map[string]string{header: "good"})
		if w.Code != http.StatusNoContent || p == nil || p.Type != typ || p.PrincipalID != header || !p.HasScope("read") || p.HasScope("write") {
			t.Errorf("%s: %d %+v", header, w.Code, p)
		}
	}
	if _, p := serve(t, requestprincipal.Options{}, map[string]string{"X-Agent": "good"}); !p.IsAgent() {
		t.Error("agent principal: IsAgent false")
	}

	// No credentials: 401 with every challenge.
	w, p := serve(t, requestprincipal.Options{}, nil)
	if w.Code != http.StatusUnauthorized || p != nil || w.Header().Get("X-Agent-Challenge") != "agent" || w.Header().Get("X-Human-Challenge") != "human" {
		t.Errorf("anonymous: %d %v", w.Code, w.Header())
	}

	// Rejected credentials end the chain with that authenticator's
	// response, even when a later authenticator would accept.
	w, _ = serve(t, requestprincipal.Options{}, map[string]string{"X-Agent": "bad", "X-Human": "good"})
	if w.Code != http.StatusForbidden || w.Header().Get("X-Human-Challenge") != "" {
		t.Errorf("rejected: %d %v", w.Code, w.Header())
	}

	// Internal errors are 500s.
	if w, _ := serve(t, requestprincipal.Options{}, map[string]string{"X-Human": "broken"}); w.Code != http.StatusInternalServerError {
		t.Errorf("internal error: %d", w.Code)
	}

	// Optional: anonymous requests pass without a principal; invalid
	// credentials are still rejected.
	if w, p := serve(t, requestprincipal.Options{Optional: true}, nil); w.Code != http.StatusNoContent || p != nil {
		t.Errorf("optional anonymous: %d %+v", w.Code, p)
	}
	if w, _ := serve(t, requestprincipal.Options{Optional: true}, map[string]string{"X-Human": "bad"}); w.Code != http.StatusForbidden {
		t.Errorf("optional invalid: %d", w.Code)
	}
}

func TestChainNoCredentials(t *testing.T) {
	chain := requestprincipal.Chain{headerAuth{header: "X-Agent", challenge: "agent"}}
	_, err := chain.Authenticate(httptest.NewRequest(http.MethodGet, "/", nil))
	var authErr *requestprincipal.Error
	if !errors.Is(err, requestprincipal.ErrNoCredentials) || !errors.As(err, &authErr) || authErr.Header.Get("X-Agent-Challenge") != "agent" {
		t.Errorf("chain without credentials: %v", err)
	}
}

func TestErrorRespond(t *testing.T) {
	e := &requestprincipal.Error{
		Header:  http.Header{"Aauth-Requirement": {"requirement=person-token"}},
		Respond: func(w http.ResponseWriter) { w.WriteHeader(http.StatusTeapot) },
	}
	w := httptest.NewRecorder()
	e.Write(w)
	if w.Code != http.StatusTeapot || w.Header().Get("AAuth-Requirement") != "requirement=person-token" {
		t.Errorf("custom response: %d %v", w.Code, w.Header())
	}
	if e.Error() == "" {
		t.Error("empty error string")
	}
}

func TestContext(t *testing.T) {
	ctx := t.Context()
	if _, ok := requestprincipal.FromContext(ctx); ok {
		t.Error("principal in empty context")
	}
	p := &requestprincipal.RequestPrincipal{PrincipalID: "p"}
	if got, ok := requestprincipal.FromContext(requestprincipal.WithPrincipal(ctx, p)); !ok || got != p {
		t.Error("principal not round-tripped")
	}
	if _, ok := requestprincipal.FromContext(requestprincipal.WithPrincipal(ctx, nil)); ok {
		t.Error("nil principal reported present")
	}
}
