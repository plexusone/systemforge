package appcatalog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewValidatesAndOrders(t *testing.T) {
	c, err := New(
		App{ID: "agents", Name: "AgentPlexus", URL: "https://agents.example.com", Order: 2},
		App{ID: "build", Name: "VisionStudio", URL: "https://app.example.com", Order: 1},
		App{ID: "docs", Name: "Docs", URL: "http://docs.localhost:8080", Order: 2},
	)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, a := range c.Apps() {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "build,agents,docs" {
		t.Errorf("order = %v, want by order then name", ids)
	}
	if a, ok := c.Get("agents"); !ok || a.Name != "AgentPlexus" {
		t.Errorf("Get = %+v, %v", a, ok)
	}

	for name, bad := range map[string]App{
		"bad id":        {ID: "Build", Name: "x", URL: "https://x.example.com"},
		"no name":       {ID: "x", Name: " ", URL: "https://x.example.com"},
		"relative url":  {ID: "x1", Name: "x", URL: "/x"},
		"plain http":    {ID: "x2", Name: "x", URL: "http://x.example.com"},
		"credentials":   {ID: "x3", Name: "x", URL: "https://u:p@x.example.com"}, //nolint:gosec // G101: a dummy credential proving such URLs are refused
		"script scheme": {ID: "x4", Name: "x", URL: "javascript:alert(1)"},
	} {
		if _, err := New(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := New(App{ID: "x", Name: "a", URL: "https://a.example.com"}, App{ID: "x", Name: "b", URL: "https://b.example.com"}); err == nil {
		t.Error("duplicate id accepted")
	}
}

func TestAppsReturnsACopy(t *testing.T) {
	c, err := New(App{ID: "build", Name: "Build", URL: "https://app.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	c.Apps()[0].Name = "changed"
	if a, _ := c.Get("build"); a.Name != "Build" {
		t.Fatal("Apps exposed the catalog")
	}
}

func TestRemoteCachesAndKeepsTheLastCatalog(t *testing.T) {
	var hits atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != WellKnownPath || fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if err := json.NewEncoder(w).Encode(Document{Apps: []App{{ID: "build", Name: "Build", URL: "https://app.example.com"}}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)

	now := time.Unix(1_000_000, 0)
	src := Remote(srv.URL+"/", srv.Client(), time.Minute).(*remoteSource)
	src.now = func() time.Time { return now }
	ctx := context.Background()

	apps, err := src.Apps(ctx)
	if err != nil || len(apps) != 1 || apps[0].ID != "build" {
		t.Fatalf("first fetch = %+v, %v", apps, err)
	}
	if _, err := src.Apps(ctx); err != nil || hits.Load() != 1 {
		t.Fatalf("within the TTL: %d fetches, %v", hits.Load(), err)
	}
	now = now.Add(2 * time.Minute)
	fail.Store(true)
	apps, err = src.Apps(ctx)
	if err != nil || len(apps) != 1 || hits.Load() != 2 {
		t.Fatalf("after expiry with SystemAuth down: %+v, %v, %d fetches", apps, err, hits.Load())
	}

	empty := Remote(srv.URL, srv.Client(), 0)
	if _, err := empty.Apps(ctx); err == nil {
		t.Fatal("a source that never fetched reported no error")
	}
}
