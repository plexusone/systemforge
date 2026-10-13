package relyingparty

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/plexusone/systemforge/identity/appcatalog"
)

type failingApps struct{}

func (failingApps) Apps(context.Context) ([]appcatalog.App, error) {
	return nil, errors.New("SystemAuth unavailable")
}

func TestBFFSessionListsTheAppCatalog(t *testing.T) {
	catalog, err := appcatalog.New(
		appcatalog.App{ID: "agents", Name: "AgentPlexus", URL: "https://agents.example.com", Order: 2},
		appcatalog.App{ID: "build", Name: "VisionStudio", URL: "https://app.example.com", Order: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	session := func(apps appcatalog.Source) (int, SessionStatus) {
		h := newHarness(t)
		h.bff.cfg.Apps = apps
		req := httptest.NewRequest(http.MethodGet, "/bff/session", nil)
		req.AddCookie(h.sessionCookie())
		w := h.do(req)
		var s SessionStatus
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatal(err)
		}
		return w.Code, s
	}

	code, s := session(appcatalog.Static(catalog))
	if code != http.StatusOK || len(s.Apps) != 2 || s.Apps[0].ID != "build" || s.Apps[1].URL != "https://agents.example.com" {
		t.Fatalf("apps = %d %+v", code, s.Apps)
	}
	// A catalog that cannot be read leaves the session intact.
	code, s = session(failingApps{})
	if code != http.StatusOK || !s.Authenticated || s.Apps != nil {
		t.Fatalf("failing catalog: %d %+v", code, s)
	}
	// Without a catalog the field is omitted.
	if _, s = session(nil); s.Apps != nil {
		t.Fatalf("apps without a catalog: %+v", s.Apps)
	}
}
