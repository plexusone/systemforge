package managedprincipal

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// maxBodyBytes bounds the JSON bodies the handler accepts.
const maxBodyBytes = 64 << 10

// ManagerView is a manager relationship as the API returns it.
type ManagerView struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	Role        string    `json:"role"`
}

// CreateRequest is the body of POST /.
type CreateRequest struct {
	// ClientID is the OAuth client making the request.
	ClientID    string        `json:"client_id"`
	DisplayName string        `json:"display_name"`
	Email       string        `json:"email,omitempty"`
	Managers    []ManagerView `json:"managers"`
	// Role, in place of Managers, makes the caller the only manager in
	// that role.
	Role string `json:"role,omitempty"`
}

// decode reads a JSON body into v, writing an error response on failure.
func (h *handler) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return false
	}
	return true
}

func (h *handler) writeCreated(w http.ResponseWriter, r *http.Request, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is already sent; the client sees a truncated body.
		h.svc.logger.ErrorContext(r.Context(), "managedprincipal: write response", "error", err)
	}
}

func (h *handler) create(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req CreateRequest
	if !h.decode(w, r, &req) {
		return
	}
	clientID, ok := h.client(w, r, req.ClientID)
	if !ok {
		return
	}
	if req.Role != "" {
		if len(req.Managers) > 0 {
			writeError(w, http.StatusBadRequest, "give managers or role, not both")
			return
		}
		req.Managers = []ManagerView{{PrincipalID: actor, Role: req.Role}}
	}
	if h.remote() && (len(req.Managers) != 1 || req.Managers[0].PrincipalID != actor) {
		writeError(w, http.StatusBadRequest, "managers must name only the caller; invite further managers")
		return
	}
	in := CreateInput{ClientID: clientID, DisplayName: req.DisplayName, Email: req.Email, ActorID: actor}
	for _, m := range req.Managers {
		in.Managers = append(in.Managers, ManagerInput(m))
	}
	id, err := h.svc.Create(r.Context(), in)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCreated(w, r, map[string]any{"id": id})
}

func (h *handler) listManagers(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	rels, err := h.svc.ListManagersFor(r.Context(), actor, managed)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	out := make([]ManagerView, 0, len(rels))
	for _, rel := range rels {
		out = append(out, ManagerView{PrincipalID: rel.ManagerPrincipalID, Role: rel.Role})
	}
	h.writeJSON(w, r, map[string]any{"managers": out})
}

func (h *handler) addManager(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	if h.remote() {
		// A manager joins with consent: through an invitation or a claim.
		writeError(w, http.StatusForbidden, "add managers through an invitation or a claim")
		return
	}
	var req ManagerView
	if !h.decode(w, r, &req) {
		return
	}
	if err := h.svc.AddManager(r.Context(), managed, ManagerInput(req), actor); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) removeManager(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	managerID, err := uuid.Parse(chi.URLParam(r, "managerID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	m := ManagerInput{PrincipalID: managerID, Role: chi.URLParam(r, "role")}
	if err := h.svc.RemoveManager(r.Context(), managed, m, actor); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) release(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	if err := h.svc.Release(r.Context(), actor, managed); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) delete(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), actor, managed); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) issueClaim(w http.ResponseWriter, r *http.Request) {
	actor, managed, ok := h.ids(w, r)
	if !ok {
		return
	}
	claim, err := h.svc.IssueClaim(r.Context(), actor, managed)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCreated(w, r, map[string]any{
		"id": claim.ID, "code": claim.Code, "expires_at": claim.ExpiresAt,
	})
}

func (h *handler) redeemClaim(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	if !h.allowCode(w, r, actor) {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !h.decode(w, r, &req) {
		return
	}
	id, err := h.svc.RedeemClaim(r.Context(), req.Code, actor)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeJSON(w, r, map[string]any{"principal_id": id})
}

func (h *handler) inviteManager(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req struct {
		ClientID string `json:"client_id"`
		Email    string `json:"email"`
		Role     string `json:"role"`
	}
	if !h.decode(w, r, &req) {
		return
	}
	clientID, ok := h.client(w, r, req.ClientID)
	if !ok {
		return
	}
	inv, err := h.svc.InviteManager(r.Context(), InviteManagerInput{ClientID: clientID, ManagerID: actor, Email: req.Email, Role: req.Role})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeCreated(w, r, map[string]any{
		"id": inv.ID, "token": inv.Token, "email": inv.Email, "role": inv.Role, "expires_at": inv.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *handler) acceptInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	if !h.allowCode(w, r, actor) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !h.decode(w, r, &req) {
		return
	}
	managerID, err := h.svc.AcceptManagerInvite(r.Context(), req.Token, actor)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.writeJSON(w, r, map[string]any{"manager_principal_id": managerID})
}

func (h *handler) declineInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	if !h.allowCode(w, r, actor) {
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if !h.decode(w, r, &req) {
		return
	}
	if err := h.svc.DeclineManagerInvite(r.Context(), req.Token, actor); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) revokeInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := h.caller(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "inviteID"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if err := h.svc.RevokeManagerInvite(r.Context(), actor, id); err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
