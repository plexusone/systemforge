// Package compose defines SystemForge's composition runtime: the Feature and
// Registrar contracts that let capabilities — a single feature slice or a
// whole application — be composed into one binary or split across services
// without changing the capabilities themselves.
//
// A Feature registers its HTTP routes through a Registrar and participates in a
// Start/Stop lifecycle. An App (see app.go) aggregates Features and is itself a
// Feature, which makes composition recursive: a host registers a whole
// application the same way an application registers one of its own features.
//
// See docs/architecture/systemforge-application-architecture.md for the
// conventions this package implements.
package compose

import (
	"context"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
)

// Feature is one registrable capability: a feature slice or a whole app.
//
// Implementations that have no startup/shutdown work can embed Base to get
// no-op Start/Stop and only implement Name and RegisterRoutes.
type Feature interface {
	// Name returns the capability's canonical slug (see the application
	// architecture guide). It must be stable and unique within a composition.
	Name() string

	// RegisterRoutes registers the capability's HTTP routes via the Registrar.
	RegisterRoutes(r Registrar) error

	// Start performs startup work (warming caches, opening consumers, etc.).
	// It may be a no-op.
	Start(ctx context.Context) error

	// Stop releases resources acquired in Start. It may be a no-op.
	Stop(ctx context.Context) error
}

// Registrar is the registration surface a Feature receives. It abstracts the
// HTTP layer so a feature registers routes without constructing the server.
//
// SystemForge is mid-migration from chi handlers to Huma operations, so the
// Registrar exposes both: HumaAPI for typed operation registration (the
// forward direction) and Mux for chi handlers not yet migrated. A feature
// should prefer HumaAPI for new endpoints.
type Registrar interface {
	// HumaAPI returns the Huma API for typed operation registration.
	HumaAPI() huma.API
	// Mux returns the underlying chi router for not-yet-migrated handlers.
	Mux() chi.Router
}

// NewRegistrar returns a Registrar backed by a Huma API and a chi router.
// Either may be nil if a composition only uses one HTTP style, but a feature
// that calls the corresponding accessor will then receive nil.
func NewRegistrar(api huma.API, mux chi.Router) Registrar {
	return &registrar{api: api, mux: mux}
}

type registrar struct {
	api huma.API
	mux chi.Router
}

func (r *registrar) HumaAPI() huma.API { return r.api }
func (r *registrar) Mux() chi.Router   { return r.mux }

// Base can be embedded in a Feature to satisfy the lifecycle methods with
// no-ops, so small features only implement Name and RegisterRoutes.
type Base struct{}

// Start is a no-op.
func (Base) Start(context.Context) error { return nil }

// Stop is a no-op.
func (Base) Stop(context.Context) error { return nil }
