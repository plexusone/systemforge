package compose

import (
	"context"
	"errors"
	"fmt"
)

// App composes Features into one unit. App is itself a Feature, so an
// application can be embedded into a larger host composition — this is what
// makes SystemForge composition recursive.
//
// An App is built during startup (before serving) and is not safe for
// concurrent modification.
type App struct {
	name     string
	features []Feature
}

// Compile-time check: an App is a Feature.
var _ Feature = (*App)(nil)

// NewApp creates an App with the given canonical name and initial features.
func NewApp(name string, features ...Feature) *App {
	return &App{name: name, features: append([]Feature(nil), features...)}
}

// Register appends features to the App, in order.
func (a *App) Register(features ...Feature) {
	a.features = append(a.features, features...)
}

// Name returns the application's canonical name.
func (a *App) Name() string { return a.name }

// Features returns the registered features in registration order.
func (a *App) Features() []Feature {
	return append([]Feature(nil), a.features...)
}

// RegisterRoutes registers every feature's routes in registration order,
// stopping at the first error.
func (a *App) RegisterRoutes(r Registrar) error {
	for _, f := range a.features {
		if err := f.RegisterRoutes(r); err != nil {
			return fmt.Errorf("compose: register routes for %q: %w", f.Name(), err)
		}
	}
	return nil
}

// Start starts features in registration order. If a feature fails to start,
// already-started features are stopped in reverse order and the error is
// returned, so a failed Start leaves nothing running.
func (a *App) Start(ctx context.Context) error {
	for i, f := range a.features {
		if err := f.Start(ctx); err != nil {
			for j := i - 1; j >= 0; j-- {
				_ = a.features[j].Stop(ctx)
			}
			return fmt.Errorf("compose: start %q: %w", f.Name(), err)
		}
	}
	return nil
}

// Stop stops features in reverse registration order, accumulating any errors
// so one feature's failure does not prevent the others from stopping.
func (a *App) Stop(ctx context.Context) error {
	var errs []error
	for i := len(a.features) - 1; i >= 0; i-- {
		f := a.features[i]
		if err := f.Stop(ctx); err != nil {
			errs = append(errs, fmt.Errorf("compose: stop %q: %w", f.Name(), err))
		}
	}
	return errors.Join(errs...)
}
