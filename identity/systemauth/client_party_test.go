package systemauth

import (
	"context"
	"errors"
	"testing"

	"github.com/plexusone/systemforge/identity/ent/oauthapp"
)

func TestConfigClientDefaultsToFirstParty(t *testing.T) {
	c, err := NewClientFromConfig(ClientConfig{ID: "app", Type: "public", Name: "App"})
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if c.Party != PartyFirst || !c.IsFirstParty() {
		t.Errorf("party = %q, want first_party", c.Party)
	}
	c, err = NewClientFromConfig(ClientConfig{ID: "partner", Type: "public", Name: "Partner", Party: "third_party"})
	if err != nil {
		t.Fatalf("NewClientFromConfig: %v", err)
	}
	if c.IsFirstParty() {
		t.Error("a configured third-party client is first-party")
	}
}

func TestRuntimeClientDefaultsToThirdParty(t *testing.T) {
	if (&Client{}).EffectiveParty() != PartyThird {
		t.Error("a client without a party is not third-party")
	}
	ctx := context.Background()
	storage := NewMemoryStorage()
	store := NewEmbeddedOAuthClientStore(storage)
	if err := store.CreateClient(ctx, &OAuthClient{ClientID: "api", ClientName: "API client", Public: true}); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}
	got, err := store.GetClient(ctx, "api")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.Party != string(PartyThird) {
		t.Errorf("party = %q, want third_party", got.Party)
	}

	// An update without a party keeps it; one with a party changes it.
	if err := store.UpdateClient(ctx, &OAuthClient{ClientID: "api", ClientName: "API client", Public: true}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if got, err = store.GetClient(ctx, "api"); err != nil || got.Party != string(PartyThird) {
		t.Fatalf("after update: %+v, %v", got, err)
	}
	if err := store.UpdateClient(ctx, &OAuthClient{ClientID: "api", ClientName: "API client", Public: true, Party: "second_party"}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	if got, err = store.GetClient(ctx, "api"); err != nil || got.Party != string(PartySecond) {
		t.Fatalf("after party update: %+v, %v", got, err)
	}
}

func TestInvalidPartyRejected(t *testing.T) {
	cfg := Config{Issuer: testIssuer, Clients: []ClientConfig{{ID: "app", Type: "public", Name: "App", Party: "fourth_party"}}}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Validate: %v, want ErrInvalidConfig", err)
	}
	if _, err := NewClientFromConfig(cfg.Clients[0]); !errors.Is(err, ErrInvalidClientParty) {
		t.Errorf("NewClientFromConfig: %v, want ErrInvalidClientParty", err)
	}
	if _, err := NewEmbedded(cfg); err == nil {
		t.Error("NewEmbedded accepted an unknown party")
	}

	s, err := NewEmbedded(Config{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if err := s.RegisterClient(&Client{ID: "x", Party: "FIRST_PARTY"}); !errors.Is(err, ErrInvalidClientParty) {
		t.Errorf("RegisterClient: %v, want ErrInvalidClientParty", err)
	}
	if err := NewMemoryStorage().CreateClient(context.Background(), &Client{ID: "x", Party: "partner"}); !errors.Is(err, ErrInvalidClientParty) {
		t.Errorf("MemoryStorage.CreateClient: %v, want ErrInvalidClientParty", err)
	}
	if err := NewEmbeddedOAuthClientStore(NewMemoryStorage()).CreateClient(context.Background(), &OAuthClient{ClientID: "x", Party: "partner"}); !errors.Is(err, ErrInvalidClientParty) {
		t.Errorf("EmbeddedOAuthClientStore.CreateClient: %v, want ErrInvalidClientParty", err)
	}
}

func TestClientLogoURLValidation(t *testing.T) {
	for _, ok := range []string{"", "https://cdn.example.com/logo.png"} {
		if err := ValidateClientLogoURL(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://cdn.example.com/logo.png",
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"//cdn.example.com/logo.png",
		"/logo.png",
		"https://user:pass@cdn.example.com/logo.png",
		"https:///logo.png",
	} {
		if err := ValidateClientLogoURL(bad); !errors.Is(err, ErrInvalidClientLogoURL) {
			t.Errorf("%q: %v, want ErrInvalidClientLogoURL", bad, err)
		}
	}
	cfg := Config{Issuer: testIssuer, Clients: []ClientConfig{{ID: "app", Type: "public", Name: "App", LogoURL: "http://x.example.com/l.png"}}}
	if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("Validate: %v, want ErrInvalidConfig", err)
	}
}

func TestEntStoragePartyRoundTrip(t *testing.T) {
	ctx := context.Background()
	db := newEntTestClient(t, "party_round_trip")
	storage := NewEntStorage(db, WithDefaultOwner(createTestOwner(t, db)))

	for _, party := range []ClientParty{PartyFirst, PartySecond, PartyThird, ""} {
		id := "app-" + string(party)
		if err := storage.CreateClient(ctx, &Client{ID: id, Type: ClientTypePublic, Name: "App", Party: party, LogoURL: "https://cdn.example.com/" + id + ".png"}); err != nil {
			t.Fatalf("CreateClient %q: %v", party, err)
		}
		got, err := storage.GetClientByID(ctx, id)
		if err != nil {
			t.Fatalf("GetClientByID: %v", err)
		}
		if got.Party != party.Effective() || got.LogoURL != "https://cdn.example.com/"+id+".png" {
			t.Errorf("party %q: read back %q, logo %q", party, got.Party, got.LogoURL)
		}
		app, err := db.OAuthApp.Query().Where(oauthapp.ClientIDEQ(id)).Only(ctx)
		if err != nil {
			t.Fatalf("query app: %v", err)
		}
		if app.Party == nil || ClientParty(*app.Party) != party.Effective() || app.FirstParty != (party == PartyFirst) {
			t.Errorf("party %q: stored party %v, first_party %v", party, app.Party, app.FirstParty)
		}
	}

	// An update changes the party and keeps first_party in step.
	if err := storage.UpdateClient(ctx, &Client{ID: "app-third_party", Type: ClientTypePublic, Name: "App", Party: PartyFirst}); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	app, err := db.OAuthApp.Query().Where(oauthapp.ClientIDEQ("app-third_party")).Only(ctx)
	if err != nil {
		t.Fatalf("query app: %v", err)
	}
	if app.Party == nil || *app.Party != oauthapp.PartyFirstParty || !app.FirstParty || app.LogoURL != "" {
		t.Errorf("after update: party %v, first_party %v, logo %q", app.Party, app.FirstParty, app.LogoURL)
	}

	// A row written before the party column existed is classified by
	// first_party.
	for _, legacy := range []struct {
		firstParty bool
		want       ClientParty
	}{{true, PartyFirst}, {false, PartyThird}} {
		app, err := db.OAuthApp.UpdateOneID(app.ID).ClearParty().SetFirstParty(legacy.firstParty).Save(ctx)
		if err != nil {
			t.Fatalf("clear party: %v", err)
		}
		if got := entAppParty(app); got != legacy.want {
			t.Errorf("legacy first_party=%v: party %q, want %q", legacy.firstParty, got, legacy.want)
		}
		fc, err := storage.GetClient(ctx, app.ClientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if fc.(*Client).IsFirstParty() != legacy.firstParty {
			t.Errorf("legacy first_party=%v: IsFirstParty %v", legacy.firstParty, !legacy.firstParty)
		}
	}

	if err := storage.CreateClient(ctx, &Client{ID: "bad", Name: "Bad", Party: "partner"}); !errors.Is(err, ErrInvalidClientParty) {
		t.Errorf("CreateClient with unknown party: %v", err)
	}
}
