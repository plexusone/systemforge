// Package featureflags provides a feature flag engine for SystemForge applications.
package featureflags

import (
	"context"
)

// Flag represents a feature flag configuration.
type Flag struct {
	// Key is the unique identifier for the flag.
	Key string `json:"key"`

	// Name is a human-readable name for the flag.
	Name string `json:"name,omitempty"`

	// Description explains what the flag controls.
	Description string `json:"description,omitempty"`

	// Enabled indicates if the flag is globally enabled.
	Enabled bool `json:"enabled"`

	// Percentage is the rollout percentage (0-100) for gradual rollouts.
	// Only applies when Enabled is true.
	Percentage int `json:"percentage,omitempty"`

	// Targets are specific user or organization IDs that should have the flag enabled.
	Targets []string `json:"targets,omitempty"`

	// Metadata holds additional flag-specific data.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Store defines the interface for feature flag storage.
type Store interface {
	// Get retrieves a flag by key.
	Get(ctx context.Context, key string) (*Flag, error)

	// GetAll retrieves all flags.
	GetAll(ctx context.Context) ([]*Flag, error)

	// Set creates or updates a flag.
	Set(ctx context.Context, flag *Flag) error

	// Delete removes a flag.
	Delete(ctx context.Context, key string) error
}

// EvaluationContext provides context for flag evaluation.
type EvaluationContext struct {
	// UserID is the current user's ID.
	UserID string

	// OrganizationID is the current organization's ID.
	OrganizationID string

	// Attributes are additional attributes for targeting.
	Attributes map[string]any
}

// Engine evaluates feature flags.
type Engine struct {
	store Store
}

// NewEngine creates a new feature flag engine.
func NewEngine(store Store) *Engine {
	return &Engine{store: store}
}

// IsEnabled checks if a feature flag is enabled for the given context.
func (e *Engine) IsEnabled(ctx context.Context, key string, evalCtx *EvaluationContext) (bool, error) {
	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return false, err
	}

	if flag == nil {
		return false, nil
	}

	return e.evaluateFlag(flag, evalCtx), nil
}

// IsEnabledSimple checks if a flag is enabled without context (global check).
// A flag restricted to targets or to a partial rollout is off without a
// subject to evaluate it for.
func (e *Engine) IsEnabledSimple(ctx context.Context, key string) (bool, error) {
	return e.IsEnabled(ctx, key, nil)
}

// GetFlag retrieves a flag by key.
func (e *Engine) GetFlag(ctx context.Context, key string) (*Flag, error) {
	return e.store.Get(ctx, key)
}

// GetAllFlags retrieves all flags.
func (e *Engine) GetAllFlags(ctx context.Context) ([]*Flag, error) {
	return e.store.GetAll(ctx)
}

// SetFlag creates or updates a flag.
func (e *Engine) SetFlag(ctx context.Context, flag *Flag) error {
	return e.store.Set(ctx, flag)
}

// DeleteFlag removes a flag.
func (e *Engine) DeleteFlag(ctx context.Context, key string) error {
	return e.store.Delete(ctx, key)
}

// evaluateFlag determines if a flag is enabled for the given context.
func (e *Engine) evaluateFlag(flag *Flag, evalCtx *EvaluationContext) bool {
	// If globally disabled, return false
	if !flag.Enabled {
		return false
	}

	// Without a subject, only an unrestricted flag is on: a flag limited
	// to targets or to a partial rollout must not be on for everyone.
	if evalCtx == nil || (evalCtx.UserID == "" && evalCtx.OrganizationID == "") {
		return !isRestricted(flag)
	}

	// Check if user or org is in targets
	if len(flag.Targets) > 0 {
		for _, target := range flag.Targets {
			if target == "" {
				continue
			}
			if target == evalCtx.UserID || target == evalCtx.OrganizationID {
				return true
			}
		}
		// If targets are specified but not matched, check percentage
		if flag.Percentage == 0 {
			return false
		}
	}

	// Check percentage rollout
	if flag.Percentage > 0 && flag.Percentage < 100 {
		// Use a deterministic hash based on user/org ID for consistent results
		id := evalCtx.UserID
		if id == "" {
			id = evalCtx.OrganizationID
		}
		if id == "" {
			return false
		}

		// Simple hash-based percentage calculation
		hash := hashString(flag.Key + ":" + id)
		return (hash % 100) < uint32(flag.Percentage)
	}

	return flag.Enabled
}

// isRestricted reports whether an enabled flag applies only to some
// subjects: it has targets or a rollout percentage below 100. Percentage 0
// without targets means no rollout limit, and 100 opens the flag to all.
func isRestricted(flag *Flag) bool {
	if flag.Percentage >= 100 {
		return false
	}
	return len(flag.Targets) > 0 || flag.Percentage > 0
}

// hashString returns a simple hash of a string.
func hashString(s string) uint32 {
	var hash uint32
	for _, c := range s {
		hash = hash*31 + uint32(c) //nolint:gosec // G115: Safe for hash computation
	}
	return hash
}

// EnableFlag enables a flag globally.
func (e *Engine) EnableFlag(ctx context.Context, key string) error {
	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return err
	}

	if flag == nil {
		flag = &Flag{Key: key}
	}

	flag.Enabled = true
	return e.store.Set(ctx, flag)
}

// DisableFlag disables a flag globally.
func (e *Engine) DisableFlag(ctx context.Context, key string) error {
	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return err
	}

	if flag == nil {
		return nil
	}

	flag.Enabled = false
	return e.store.Set(ctx, flag)
}

// SetPercentage sets the rollout percentage for a flag.
func (e *Engine) SetPercentage(ctx context.Context, key string, percentage int) error {
	if percentage < 0 {
		percentage = 0
	}
	if percentage > 100 {
		percentage = 100
	}

	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return err
	}

	if flag == nil {
		flag = &Flag{Key: key, Enabled: true}
	}

	flag.Percentage = percentage
	return e.store.Set(ctx, flag)
}

// AddTarget adds a target (user or org ID) to a flag.
func (e *Engine) AddTarget(ctx context.Context, key, targetID string) error {
	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return err
	}

	if flag == nil {
		flag = &Flag{Key: key, Enabled: true}
	}

	// Check if target already exists
	for _, t := range flag.Targets {
		if t == targetID {
			return nil
		}
	}

	flag.Targets = append(flag.Targets, targetID)
	return e.store.Set(ctx, flag)
}

// RemoveTarget removes a target from a flag.
func (e *Engine) RemoveTarget(ctx context.Context, key, targetID string) error {
	flag, err := e.store.Get(ctx, key)
	if err != nil {
		return err
	}

	if flag == nil {
		return nil
	}

	targets := make([]string, 0, len(flag.Targets))
	for _, t := range flag.Targets {
		if t != targetID {
			targets = append(targets, t)
		}
	}
	flag.Targets = targets

	return e.store.Set(ctx, flag)
}
