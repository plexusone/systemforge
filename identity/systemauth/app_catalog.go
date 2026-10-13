package systemauth

import (
	"encoding/json"
	"net/http"

	"github.com/plexusone/systemforge/identity/appcatalog"
)

// WithAppCatalog publishes the deployment's application catalog at
// appcatalog.WellKnownPath, for relying parties to list in the product
// switcher. The catalog is public: names and launch URLs are not secret,
// and which applications a person sees is decided by their orgs claim.
func WithAppCatalog(c *appcatalog.Catalog) Option {
	return func(s *Server) { s.appCatalog = c }
}

// handleAppCatalog serves GET appcatalog.WellKnownPath.
func (s *Server) handleAppCatalog(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(s.appCatalog.Document()); err != nil {
		LoggerFromContext(r.Context()).Error("writing the app catalog", "error", err)
	}
}
