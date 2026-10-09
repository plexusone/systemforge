package principal_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/authz/noop"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/enttest"
	"github.com/plexusone/systemforge/identity/principal"
)

// adminSyncer records platform-admin syncs and principal registrations.
type adminSyncer struct {
	noop.Syncer
	mu         sync.Mutex
	admins     map[uuid.UUID]bool
	registered []uuid.UUID
	fail       error
}

func (s *adminSyncer) RegisterPrincipal(_ context.Context, id uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.registered = append(s.registered, id)
	return s.fail
}

func (s *adminSyncer) SetPlatformAdmin(_ context.Context, id uuid.UUID, admin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admins[id] = admin
	return s.fail
}

func newService(t *testing.T, opts ...principal.ServiceOption) (principal.Service, *ent.Client, *adminSyncer) {
	t.Helper()
	db := enttest.Open(t, "sqlite3", "file:"+uuid.NewString()+"?mode=memory&cache=shared&_fk=1")
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	syncer := &adminSyncer{admins: map[uuid.UUID]bool{}}
	return principal.NewService(db, append([]principal.ServiceOption{principal.WithAuthzSyncer(syncer), principal.WithSyncMode(authz.SyncModeStrict)}, opts...)...), db, syncer
}

func TestCreateAndGetEachType(t *testing.T) {
	ctx := context.Background()
	svc, _, syncer := newService(t)

	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim", GivenName: "Kim", Locale: "en"})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if h.Type != principal.TypeHuman || h.Identifier != "kim@example.com" || h.Human == nil || h.Human.Email != "kim@example.com" || !h.Active {
		t.Errorf("human = %+v", h)
	}
	if !h.Capabilities.CanAccessUI {
		t.Errorf("human capabilities = %+v", h.Capabilities)
	}
	if got, err := svc.GetByIdentifier(ctx, "kim@example.com"); err != nil || got.ID != h.ID || got.Human == nil {
		t.Errorf("GetByIdentifier = %+v, %v", got, err)
	}

	app, err := svc.CreateApplication(ctx, principal.CreateApplicationInput{ClientID: "billing", DisplayName: "Billing",
		AppType: principal.AppTypeSPA, RedirectURIs: []string{"https://app.example.com/cb"}, Public: true})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}
	if app.Application == nil || app.Application.ClientID != "billing" || app.Application.AccessTokenTTLSeconds != 600 || !app.Application.Public {
		t.Errorf("application = %+v", app.Application)
	}

	agent, err := svc.CreateAgent(ctx, principal.CreateAgentInput{Identifier: "agent-1", DisplayName: "Helper", ModelID: "model-x",
		DelegatingPrincipalID: &h.ID, RequiresConfirmation: true})
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if agent.Agent == nil || agent.Agent.DelegatingPrincipalID == nil || *agent.Agent.DelegatingPrincipalID != h.ID || agent.Agent.MaxTokenLifetimeSeconds != 3600 {
		t.Errorf("agent = %+v", agent.Agent)
	}

	svcP, err := svc.CreateService(ctx, principal.CreateServiceInput{Identifier: "worker", DisplayName: "Worker", ServiceType: "batch"})
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	if svcP.Service == nil || svcP.Service.ServiceType != "batch" {
		t.Errorf("service = %+v", svcP.Service)
	}

	for _, p := range []*principal.Principal{h, app, agent, svcP} {
		got, err := svc.GetByID(ctx, p.ID)
		if err != nil || got.Type != p.Type {
			t.Errorf("GetByID(%s) = %+v, %v", p.Type, got, err)
		}
	}
	if len(syncer.registered) != 4 {
		t.Errorf("registered %d principals with authz, want 4", len(syncer.registered))
	}
	if _, err := svc.GetByID(ctx, uuid.New()); err == nil {
		t.Error("GetByID of an unknown principal succeeded")
	}
	if _, err := svc.GetByIdentifier(ctx, "nobody@example.com"); err == nil {
		t.Error("GetByIdentifier of an unknown identifier succeeded")
	}
}

func TestCreateRefusals(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newService(t)

	if _, err := svc.CreateHuman(ctx, principal.CreateHumanInput{DisplayName: "No Email"}); !errors.Is(err, principal.ErrEmailRequired) {
		t.Errorf("human without email = %v", err)
	}
	if _, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"}); err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if _, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim again"}); err == nil {
		t.Error("duplicate email accepted")
	}

	// An agent must act for a principal that exists and is active.
	unknown := uuid.New()
	if _, err := svc.CreateAgent(ctx, principal.CreateAgentInput{Identifier: "a1", DisplayName: "A", ModelID: "m", DelegatingPrincipalID: &unknown}); !errors.Is(err, principal.ErrInvalidDelegator) {
		t.Errorf("unknown delegator = %v", err)
	}
	gone, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "gone@example.com", DisplayName: "Gone"})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.Deactivate(ctx, gone.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if _, err := svc.CreateAgent(ctx, principal.CreateAgentInput{Identifier: "a2", DisplayName: "A", ModelID: "m", DelegatingPrincipalID: &gone.ID}); !errors.Is(err, principal.ErrInvalidDelegator) {
		t.Errorf("inactive delegator = %v", err)
	}
}

// TestFailedSyncInStrictMode verifies that strict mode reports a failed
// authorization sync.
func TestFailedSyncInStrictMode(t *testing.T) {
	ctx := context.Background()
	svc, _, syncer := newService(t)
	syncer.fail = errors.New("authz down")
	if _, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"}); err == nil {
		t.Error("strict sync failure not reported")
	}
	eventual, _, failing := newService(t, principal.WithSyncMode(authz.SyncModeEventual))
	failing.fail = errors.New("authz down")
	if _, err := eventual.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"}); err != nil {
		t.Errorf("eventual sync failure returned: %v", err)
	}
}

func TestUpdates(t *testing.T) {
	ctx := context.Background()
	svc, _, syncer := newService(t)
	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	app, err := svc.CreateApplication(ctx, principal.CreateApplicationInput{ClientID: "billing", DisplayName: "Billing"})
	if err != nil {
		t.Fatalf("CreateApplication: %v", err)
	}

	name, locale := "Kim Lee", "fr"
	got, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{UpdateInput: principal.UpdateInput{DisplayName: &name}, Locale: &locale})
	if err != nil || got.DisplayName != name || got.Human.Locale != locale {
		t.Fatalf("UpdateHuman = %+v, %v", got, err)
	}

	// A type mismatch is refused before anything changes.
	other := "Changed"
	if _, err := svc.UpdateHuman(ctx, app.ID, principal.UpdateHumanInput{UpdateInput: principal.UpdateInput{DisplayName: &other}}); !errors.Is(err, principal.ErrWrongType) {
		t.Errorf("UpdateHuman on an application = %v, want ErrWrongType", err)
	}
	if got, err := svc.GetByID(ctx, app.ID); err != nil || got.DisplayName != "Billing" {
		t.Errorf("application after refused update = %+v, %v", got, err)
	}
	if _, err := svc.UpdateApplication(ctx, h.ID, principal.UpdateApplicationInput{UpdateInput: principal.UpdateInput{DisplayName: &other}}); !errors.Is(err, principal.ErrWrongType) {
		t.Errorf("UpdateApplication on a human = %v", err)
	}
	if _, err := svc.UpdateAgent(ctx, h.ID, principal.UpdateAgentInput{}); !errors.Is(err, principal.ErrWrongType) {
		t.Errorf("UpdateAgent on a human = %v", err)
	}
	if _, err := svc.UpdateService(ctx, h.ID, principal.UpdateServiceInput{}); !errors.Is(err, principal.ErrWrongType) {
		t.Errorf("UpdateService on a human = %v", err)
	}
	if _, err := svc.UpdateHuman(ctx, uuid.New(), principal.UpdateHumanInput{}); !errors.Is(err, principal.ErrNotFound) {
		t.Errorf("UpdateHuman on an unknown principal = %v", err)
	}
	if got, err := svc.GetByID(ctx, h.ID); err != nil || got.DisplayName != name {
		t.Errorf("human after refused updates = %+v, %v", got, err)
	}

	// Granting and revoking platform admin reach the authorization backend.
	yes, no := true, false
	if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &yes}); err != nil {
		t.Fatalf("grant platform admin: %v", err)
	}
	if !syncer.admins[h.ID] {
		t.Error("granting platform admin was not synced")
	}
	if _, err := svc.UpdateHuman(ctx, h.ID, principal.UpdateHumanInput{IsPlatformAdmin: &no}); err != nil {
		t.Fatalf("revoke platform admin: %v", err)
	}
	if admin, ok := syncer.admins[h.ID]; !ok || admin {
		t.Error("revoking platform admin was not synced")
	}

	ttl := 60
	got, err = svc.UpdateApplication(ctx, app.ID, principal.UpdateApplicationInput{AccessTokenTTLSeconds: &ttl, RedirectURIs: []string{"https://x.example/cb"}})
	if err != nil || got.Application.AccessTokenTTLSeconds != 60 || len(got.Application.RedirectURIs) != 1 {
		t.Errorf("UpdateApplication = %+v, %v", got, err)
	}
}

func TestActivationAndLogin(t *testing.T) {
	ctx := context.Background()
	svc, db, _ := newService(t)
	h, err := svc.CreateHuman(ctx, principal.CreateHumanInput{Email: "kim@example.com", DisplayName: "Kim"})
	if err != nil {
		t.Fatalf("CreateHuman: %v", err)
	}
	if err := svc.Deactivate(ctx, h.ID); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if got, err := svc.GetByID(ctx, h.ID); err != nil || got.Active {
		t.Errorf("after Deactivate = %+v, %v", got, err)
	}
	if err := svc.Reactivate(ctx, h.ID); err != nil {
		t.Fatalf("Reactivate: %v", err)
	}
	if got, err := svc.GetByID(ctx, h.ID); err != nil || !got.Active {
		t.Errorf("after Reactivate = %+v, %v", got, err)
	}
	if err := svc.Deactivate(ctx, uuid.New()); err == nil {
		t.Error("deactivating an unknown principal succeeded")
	}

	impl := svc.(*principal.DefaultService)
	if err := impl.UpdateLastLogin(ctx, h.ID); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}
	if err := impl.MarkEmailVerified(ctx, h.ID); err != nil {
		t.Fatalf("MarkEmailVerified: %v", err)
	}
	row, err := db.Human.Query().Only(ctx)
	if err != nil || row.LastLoginAt == nil || row.EmailVerifiedAt == nil {
		t.Errorf("human after login and verification = %+v, %v", row, err)
	}

	worker, err := svc.CreateService(ctx, principal.CreateServiceInput{Identifier: "worker", DisplayName: "W", ServiceType: "batch"})
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
	if err := impl.UpdateLastLogin(ctx, worker.ID); err == nil {
		t.Error("UpdateLastLogin on a service principal succeeded")
	}
	if err := impl.MarkEmailVerified(ctx, worker.ID); err == nil {
		t.Error("MarkEmailVerified on a service principal succeeded")
	}
}
