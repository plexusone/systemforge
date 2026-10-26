// Package example provides a minimal example of implementing the AppBackend interface.
// This demonstrates how to create an app that can run in both multi-app and single-app modes.
package example

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"

	"entgo.io/ent"
	"github.com/go-chi/chi/v5"
	"github.com/plexusone/systemforge/multiapp"
)

// ExampleApp is a minimal implementation of the AppBackend interface.
// It demonstrates the core patterns for building multi-app compatible backends.
type ExampleApp struct {
	deps multiapp.Dependencies
}

// NewExampleApp creates a new example app.
func NewExampleApp() *ExampleApp {
	return &ExampleApp{}
}

// Slug returns the app's unique identifier.
func (a *ExampleApp) Slug() string {
	return "example"
}

// Name returns the app's display name.
func (a *ExampleApp) Name() string {
	return "Example App"
}

// EntSchemas returns Ent schemas for this app.
// This example uses raw SQL migrations instead of Ent schemas.
func (a *ExampleApp) EntSchemas() []ent.Schema {
	return nil
}

// Migrations returns database migrations for this app.
// Each migration runs in the app's schema (e.g., app_example) with the
// migration (owner) login, never the app's own login.
func (a *ExampleApp) Migrations() []multiapp.Migration {
	return []multiapp.Migration{
		{
			Version: 1,
			Name:    "create_items_table",
			Up: func(ctx context.Context, db *multiapp.SchemaDB) error {
				_, err := db.Exec(ctx, `
					CREATE TABLE IF NOT EXISTS items (
						id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
						name TEXT NOT NULL,
						description TEXT,
						created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
						updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
					)
				`)
				return err
			},
			Down: func(ctx context.Context, db *multiapp.SchemaDB) error {
				_, err := db.Exec(ctx, `DROP TABLE IF EXISTS items`)
				return err
			},
		},
	}
}

// Routes returns the app's HTTP routes.
// These routes will be mounted at / in single-app mode,
// or dispatched via X-App-ID in multi-app mode.
func (a *ExampleApp) Routes(deps multiapp.Dependencies) chi.Router {
	a.deps = deps
	r := chi.NewRouter()

	// Health check
	r.Get("/health", a.handleHealth)

	// Items CRUD
	r.Route("/api/items", func(r chi.Router) {
		r.Get("/", a.handleListItems)
		r.Post("/", a.handleCreateItem)
		r.Get("/{id}", a.handleGetItem)
		r.Put("/{id}", a.handleUpdateItem)
		r.Delete("/{id}", a.handleDeleteItem)
	})

	// App info endpoint
	r.Get("/api/info", a.handleInfo)

	return r
}

// OnRegister is called when the app is registered with the server.
// Use this for one-time initialization that requires the app config.
func (a *ExampleApp) OnRegister(ctx context.Context, cfg *multiapp.AppConfig) error {
	a.deps.Logger.Info("app registered",
		"app_id", cfg.AppID,
		"schema", cfg.DatabaseSchema,
	)
	return nil
}

// OnShutdown is called during graceful shutdown.
// Use this to clean up resources.
func (a *ExampleApp) OnShutdown(ctx context.Context) error {
	a.deps.Logger.Info("app shutting down")
	return nil
}

// --- Handlers ---

func (a *ExampleApp) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ok",
		"app":    a.Slug(),
	})
}

func (a *ExampleApp) handleInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get app context (available in multi-app mode)
	appCtx := multiapp.AppContextFromContext(ctx)

	info := map[string]any{
		"app_slug": a.Slug(),
		"app_name": a.Name(),
	}

	if appCtx != nil {
		info["app_id"] = appCtx.AppID
		info["database_schema"] = appCtx.DatabaseSchema
		info["features"] = appCtx.Features
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(info)
}

// Item represents a sample data model.
type Item struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (a *ExampleApp) handleListItems(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rows, err := a.deps.DB.Query(ctx, `
		SELECT id, name, description, created_at, updated_at
		FROM items
		ORDER BY created_at DESC
		LIMIT 100
	`)
	if err != nil {
		a.deps.Logger.Error("failed to list items", slog.Any("error", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []Item
	for rows.Next() {
		var item Item
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.CreatedAt, &item.UpdatedAt); err != nil {
			a.deps.Logger.Error("failed to scan item", slog.Any("error", err))
			continue
		}
		items = append(items, item)
	}

	if items == nil {
		items = []Item{} // Return empty array instead of null
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(items)
}

func (a *ExampleApp) handleCreateItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if input.Name == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	var item Item
	err := a.deps.DB.QueryRow(ctx, `
		INSERT INTO items (name, description)
		VALUES ($1, $2)
		RETURNING id, name, description, created_at, updated_at
	`, input.Name, input.Description).Scan(
		&item.ID, &item.Name, &item.Description, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		a.deps.Logger.Error("failed to create item", slog.Any("error", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(item)
}

func (a *ExampleApp) handleGetItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var item Item
	err := a.deps.DB.QueryRow(ctx, `
		SELECT id, name, description, created_at, updated_at
		FROM items
		WHERE id = $1
	`, id).Scan(&item.ID, &item.Name, &item.Description, &item.CreatedAt, &item.UpdatedAt)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}

func (a *ExampleApp) handleUpdateItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	var input struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var item Item
	err := a.deps.DB.QueryRow(ctx, `
		UPDATE items
		SET name = $2, description = $3, updated_at = NOW()
		WHERE id = $1
		RETURNING id, name, description, created_at, updated_at
	`, id, input.Name, input.Description).Scan(
		&item.ID, &item.Name, &item.Description, &item.CreatedAt, &item.UpdatedAt,
	)
	if err != nil {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(item)
}

func (a *ExampleApp) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	result, err := a.deps.DB.Exec(ctx, `DELETE FROM items WHERE id = $1`, id)
	if err != nil {
		a.deps.Logger.Error("failed to delete item", slog.Any("error", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if result.RowsAffected() == 0 {
		http.Error(w, "Item not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
