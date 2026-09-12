package compose

import (
	"context"
	"errors"
	"testing"

	"github.com/go-chi/chi/v5"
)

// recorder is a test Feature that records lifecycle calls into a shared log.
type recorder struct {
	Base
	name      string
	log       *[]string
	startErr  error
	stopErr   error
	routesErr error
}

func (r *recorder) Name() string { return r.name }

func (r *recorder) RegisterRoutes(Registrar) error {
	*r.log = append(*r.log, "routes:"+r.name)
	return r.routesErr
}

func (r *recorder) Start(context.Context) error {
	*r.log = append(*r.log, "start:"+r.name)
	return r.startErr
}

func (r *recorder) Stop(context.Context) error {
	*r.log = append(*r.log, "stop:"+r.name)
	return r.stopErr
}

func TestAppIsFeature(t *testing.T) {
	var _ Feature = NewApp("x")
}

func TestAppFeaturesOrderAndRegister(t *testing.T) {
	log := []string{}
	a := NewApp("app", &recorder{name: "a", log: &log})
	a.Register(&recorder{name: "b", log: &log}, &recorder{name: "c", log: &log})

	got := a.Features()
	if len(got) != 3 {
		t.Fatalf("want 3 features, got %d", len(got))
	}
	names := []string{got[0].Name(), got[1].Name(), got[2].Name()}
	want := []string{"a", "b", "c"}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("feature order: want %v, got %v", want, names)
		}
	}

	// Features() must return a copy — mutating it must not affect the App.
	got[0] = nil
	if a.Features()[0] == nil {
		t.Fatal("Features() leaked the internal slice")
	}
}

func TestRegisterRoutesOrderAndError(t *testing.T) {
	log := []string{}
	a := NewApp("app",
		&recorder{name: "a", log: &log},
		&recorder{name: "b", log: &log},
	)
	if err := a.RegisterRoutes(NewRegistrar(nil, chi.NewRouter())); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertOrder(t, log, []string{"routes:a", "routes:b"})

	// A failing feature aborts registration at that point.
	log = nil
	boom := errors.New("boom")
	a2 := NewApp("app",
		&recorder{name: "a", log: &log},
		&recorder{name: "b", log: &log, routesErr: boom},
		&recorder{name: "c", log: &log},
	)
	err := a2.RegisterRoutes(NewRegistrar(nil, chi.NewRouter()))
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	assertOrder(t, log, []string{"routes:a", "routes:b"}) // c not reached
}

func TestStartStopOrder(t *testing.T) {
	log := []string{}
	a := NewApp("app",
		&recorder{name: "a", log: &log},
		&recorder{name: "b", log: &log},
		&recorder{name: "c", log: &log},
	)
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := a.Stop(context.Background()); err != nil {
		t.Fatalf("stop: %v", err)
	}
	assertOrder(t, log, []string{
		"start:a", "start:b", "start:c", // forward
		"stop:c", "stop:b", "stop:a", // reverse
	})
}

func TestStartRollsBackOnFailure(t *testing.T) {
	log := []string{}
	boom := errors.New("boom")
	a := NewApp("app",
		&recorder{name: "a", log: &log},
		&recorder{name: "b", log: &log},
		&recorder{name: "c", log: &log, startErr: boom},
		&recorder{name: "d", log: &log},
	)
	err := a.Start(context.Background())
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	// a,b start; c fails; b,a rolled back in reverse; d never starts.
	assertOrder(t, log, []string{
		"start:a", "start:b", "start:c", "stop:b", "stop:a",
	})
}

func TestStopAggregatesErrors(t *testing.T) {
	log := []string{}
	e1 := errors.New("e1")
	e2 := errors.New("e2")
	a := NewApp("app",
		&recorder{name: "a", log: &log, stopErr: e1},
		&recorder{name: "b", log: &log, stopErr: e2},
	)
	err := a.Stop(context.Background())
	if !errors.Is(err, e1) || !errors.Is(err, e2) {
		t.Fatalf("want both e1 and e2 joined, got %v", err)
	}
}

func TestBaseIsNoOp(t *testing.T) {
	var b Base
	if err := b.Start(context.Background()); err != nil {
		t.Fatalf("Base.Start: %v", err)
	}
	if err := b.Stop(context.Background()); err != nil {
		t.Fatalf("Base.Stop: %v", err)
	}
}

func TestRegistrarAccessors(t *testing.T) {
	mux := chi.NewRouter()
	r := NewRegistrar(nil, mux)
	if r.Mux() != mux {
		t.Fatal("Mux() did not return the provided router")
	}
	if r.HumaAPI() != nil {
		t.Fatal("HumaAPI() should be nil when constructed with nil")
	}
}

func assertOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("want %v, got %v", want, got)
		}
	}
}
