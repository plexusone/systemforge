package systemauth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Health endpoints for process supervisors and load balancers.
const (
	// HealthzPath reports liveness: the process is serving HTTP.
	HealthzPath = "/healthz"
	// ReadyzPath reports readiness: every registered check (e.g. the
	// database ping) passes.
	ReadyzPath = "/readyz"

	readinessTimeout = 3 * time.Second
)

// readinessCheck is a named dependency check.
type readinessCheck struct {
	name  string
	check func(context.Context) error
}

// WithReadinessCheck adds a dependency check to GET /readyz, e.g. a
// database ping. All checks must pass for the server to report ready.
func WithReadinessCheck(name string, check func(context.Context) error) Option {
	return func(s *Server) {
		s.readiness = append(s.readiness, readinessCheck{name: name, check: check})
	}
}

// healthResponse is the body of /healthz and /readyz.
type healthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks,omitempty"`
}

func writeHealth(w http.ResponseWriter, r *http.Request, status int, body healthResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		LoggerFromContext(r.Context()).Debug("writing health response", "error", err)
	}
}

// handleHealthz serves GET /healthz.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeHealth(w, r, http.StatusOK, healthResponse{Status: "ok"})
}

// handleReadyz serves GET /readyz. Failure details are logged, not
// returned, so the endpoint can be public.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	resp := healthResponse{Status: "ok", Checks: map[string]string{}}
	status := http.StatusOK
	for _, c := range s.readiness {
		if err := c.check(ctx); err != nil {
			LoggerFromContext(ctx).Warn("readiness check failed", "check", c.name, "error", err)
			resp.Checks[c.name] = "fail"
			resp.Status = "unavailable"
			status = http.StatusServiceUnavailable
			continue
		}
		resp.Checks[c.name] = "ok"
	}
	writeHealth(w, r, status, resp)
}
