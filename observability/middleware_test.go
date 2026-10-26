package observability

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/plexusone/omniobserve/observops"
)

// recordingProvider is a noop provider whose spans keep the attributes set
// on them.
type recordingProvider struct {
	noopProvider
	spans []*recordingSpan
}

func (p *recordingProvider) Tracer() observops.Tracer { return &recordingTracer{p: p} }

type recordingTracer struct {
	noopTracer
	p *recordingProvider
}

func (t *recordingTracer) Start(ctx context.Context, _ string, _ ...observops.SpanOption) (context.Context, observops.Span) {
	s := &recordingSpan{}
	t.p.spans = append(t.p.spans, s)
	return ctx, s
}

type recordingSpan struct {
	noopSpan
	attrs []observops.KeyValue
}

func (s *recordingSpan) SetAttributes(attrs ...observops.KeyValue) {
	s.attrs = append(s.attrs, attrs...)
}

func (s *recordingSpan) attr(key string) (any, bool) {
	for _, kv := range s.attrs {
		if kv.Key == key {
			return kv.Value, true
		}
	}
	return nil, false
}

func newRecordingObservability() (*Observability, *recordingProvider) {
	p := &recordingProvider{}
	o := newNoop()
	o.provider = p
	return o, p
}

const callbackQuery = "code=secret-auth-code&state=secret-state"

// The request's query string and path must not reach span attributes.
func TestRequestAttributesOmitURL(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/invites/secret-invite-token?"+callbackQuery, nil)
	for _, kv := range requestAttributes(req) {
		v := fmt.Sprint(kv.Value)
		if strings.Contains(v, "secret") || strings.Contains(v, "/invites") {
			t.Errorf("attribute %s = %q exposes the request URL", kv.Key, v)
		}
	}
}

func TestMiddlewareRecordsRoutePattern(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	mux := http.NewServeMux()
	mux.Handle("GET /invites/{token}", ok)

	r := chi.NewRouter()

	tests := []struct {
		name    string
		handler func(*Observability) http.Handler
		target  string
		want    string
	}{
		{"servemux", func(o *Observability) http.Handler { return o.Middleware()(mux) }, "/invites/secret-invite-token?" + callbackQuery, "GET /invites/{token}"},
		{"servemux unmatched", func(o *Observability) http.Handler { return o.Middleware()(mux) }, "/secret-unknown-path", RouteUnmatched},
		{"chi", func(o *Observability) http.Handler {
			r.Use(o.Middleware())
			r.Get("/invites/{token}", ok)
			return r
		}, "/invites/secret-invite-token?" + callbackQuery, "/invites/{token}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			o, p := newRecordingObservability()
			tc.handler(o).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, tc.target, nil))
			if len(p.spans) != 1 {
				t.Fatalf("got %d spans, want 1", len(p.spans))
			}
			got, found := p.spans[0].attr("http.route")
			if !found {
				t.Fatal("no http.route attribute")
			}
			if got != tc.want {
				t.Errorf("http.route = %q, want %q", got, tc.want)
			}
			for _, kv := range p.spans[0].attrs {
				if strings.Contains(fmt.Sprint(kv.Value), "secret") {
					t.Errorf("attribute %s = %v exposes the request URL", kv.Key, kv.Value)
				}
			}
		})
	}
}
