// Package signupapi serves the HTTP API for invite-gated sign-up: operator
// routes for email invites, invite codes, the waitlist, member allowances
// and the accounts invites admitted, and member routes for a person's own
// invite codes.
//
// The handler does not authenticate anyone itself. The host passes how to
// find the signed-in person (Options.Principal) and whether they are a
// platform administrator (Options.IsAdmin), so the same handler can sit
// behind SystemAuth's login session or behind a host application's own
// session. Mount it under a prefix with http.StripPrefix; routes are
// relative to it.
//
// JSON is snake_case like the rest of SystemAuth, lists are wrapped in a
// named key, and errors are {"error": "..."}. Responses are never cached,
// and state-changing requests from another origin are refused.
package signupapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/identity/signupgate"
)

// Options configure the API.
type Options struct {
	// Invites, Codes and Waitlist are the stores the API manages. Codes
	// carries the member invite settings. All three are required.
	Invites  *signupgate.Store
	Codes    *signupgate.CodeStore
	Waitlist *signupgate.Waitlist

	// Principal returns the signed-in person, or an error when the request
	// has no valid session. Required.
	Principal func(*http.Request) (uuid.UUID, error)
	// IsAdmin reports whether a person is a platform administrator, who may
	// use the operator routes. Required.
	IsAdmin func(context.Context, uuid.UUID) (bool, error)

	// SignupURL is the sign-up page invite links open, such as
	// https://auth.example.com/signup. Without it, responses carry the code
	// but no link.
	SignupURL string

	// Audit receives an event for every change. Optional.
	Audit audit.Emitter
	// Logger defaults to slog.Default.
	Logger *slog.Logger
}

const (
	maxBodyBytes      = 64 << 10
	maxEmailsPerCall  = 500
	maxExpiresInDays  = 3650
	maxUsesPerCode    = 1_000_000
	statusAll         = "all"
	statusActive      = "active"
	statusPendingOnly = "pending"
)

type api struct {
	o Options
}

// New returns the API handler.
func New(o Options) (http.Handler, error) {
	if o.Invites == nil || o.Codes == nil || o.Waitlist == nil {
		return nil, errors.New("signupapi: Invites, Codes and Waitlist are required")
	}
	if o.Principal == nil || o.IsAdmin == nil {
		return nil, errors.New("signupapi: Principal and IsAdmin are required")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	a := &api{o: o}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /settings", a.member(a.settings))
	mux.HandleFunc("GET /me/invites", a.member(a.myInvites))
	mux.HandleFunc("POST /me/codes", a.member(a.createMyCode))
	mux.HandleFunc("POST /me/codes/{id}/revoke", a.member(a.revokeMyCode))

	mux.HandleFunc("GET /admin/invites", a.admin(a.listInvites))
	mux.HandleFunc("POST /admin/invites", a.admin(a.addInvites))
	mux.HandleFunc("DELETE /admin/invites/{email}", a.admin(a.revokeInvite))
	mux.HandleFunc("GET /admin/codes", a.admin(a.listCodes))
	mux.HandleFunc("POST /admin/codes", a.admin(a.createCode))
	mux.HandleFunc("POST /admin/codes/{id}/revoke", a.admin(a.revokeCode))
	mux.HandleFunc("GET /admin/waitlist", a.admin(a.listWaitlist))
	mux.HandleFunc("POST /admin/waitlist/invite", a.admin(a.inviteWaitlist))
	mux.HandleFunc("DELETE /admin/waitlist/{email}", a.admin(a.removeWaitlist))
	mux.HandleFunc("GET /admin/allowances", a.admin(a.listAllowances))
	mux.HandleFunc("PUT /admin/allowances", a.admin(a.setAllowance))
	mux.HandleFunc("GET /admin/joined", a.admin(a.joined))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, "not found")
	})
	return noStore(http.NewCrossOriginProtection().Handler(mux)), nil
}

func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// handlerFunc is a route given the signed-in person.
type handlerFunc func(w http.ResponseWriter, r *http.Request, caller uuid.UUID)

// member requires a signed-in person.
func (a *api) member(h handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller, err := a.o.Principal(r)
		if err != nil || caller == uuid.Nil {
			writeError(w, http.StatusUnauthorized, "sign in required")
			return
		}
		h(w, r, caller)
	}
}

// admin requires a signed-in platform administrator.
func (a *api) admin(h handlerFunc) http.HandlerFunc {
	return a.member(func(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
		ok, err := a.o.IsAdmin(r.Context(), caller)
		if err != nil {
			a.internal(w, r, "checking platform administration", err)
			return
		}
		if !ok {
			writeError(w, http.StatusForbidden, "platform administrators only")
			return
		}
		h(w, r, caller)
	})
}

// --- wire types ---

type codeJSON struct {
	ID                   uuid.UUID  `json:"id"`
	Kind                 string     `json:"kind"`
	Hint                 string     `json:"hint"`
	Label                string     `json:"label,omitempty"`
	Note                 string     `json:"note,omitempty"`
	CreatedByPrincipalID *uuid.UUID `json:"created_by_principal_id,omitempty"`
	CreatedByLabel       string     `json:"created_by_label,omitempty"`
	MaxUses              int        `json:"max_uses"`
	UseCount             int        `json:"use_count"`
	Status               string     `json:"status"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
}

func toCodeJSON(c signupgate.Code, now time.Time) codeJSON {
	return codeJSON{
		ID: c.ID, Kind: string(c.Kind), Hint: c.Hint, Label: c.Label, Note: c.Note,
		CreatedByPrincipalID: c.CreatedByPrincipal, CreatedByLabel: c.CreatedByLabel,
		MaxUses: c.MaxUses, UseCount: c.UseCount, Status: c.Status(now),
		CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt, RevokedAt: c.RevokedAt,
	}
}

func toCodesJSON(codes []signupgate.Code, now time.Time) []codeJSON {
	out := make([]codeJSON, 0, len(codes))
	for _, c := range codes {
		out = append(out, toCodeJSON(c, now))
	}
	return out
}

// createdCodeJSON is a new code: shown once, with its link.
type createdCodeJSON struct {
	Code       codeJSON `json:"code"`
	InviteCode string   `json:"invite_code"`
	Link       string   `json:"link,omitempty"`
}

type inviteJSON struct {
	Email                string     `json:"email"`
	Note                 string     `json:"note,omitempty"`
	InvitedBy            string     `json:"invited_by,omitempty"`
	InvitedByPrincipalID *uuid.UUID `json:"invited_by_principal_id,omitempty"`
	Status               string     `json:"status"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            *time.Time `json:"expires_at,omitempty"`
	RedeemedAt           *time.Time `json:"redeemed_at,omitempty"`
	RedeemedBy           *uuid.UUID `json:"redeemed_by,omitempty"`
}

func toInviteJSON(i signupgate.Invite, now time.Time) inviteJSON {
	return inviteJSON{
		Email: i.Email, Note: i.Note, InvitedBy: i.InvitedBy, InvitedByPrincipalID: i.InvitedByPrincipal,
		Status: i.Status(now), CreatedAt: i.CreatedAt, ExpiresAt: i.ExpiresAt,
		RedeemedAt: i.RedeemedAt, RedeemedBy: i.RedeemedBy,
	}
}

type waitlistJSON struct {
	Email           string     `json:"email"`
	ConsentVersion  string     `json:"consent_version"`
	JoinedAt        time.Time  `json:"joined_at"`
	LastSubmittedAt time.Time  `json:"last_submitted_at"`
	InvitedAt       *time.Time `json:"invited_at,omitempty"`
}

type allowanceJSON struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	Email       string    `json:"email"`
	Granted     *int      `json:"granted"`
	Effective   int       `json:"effective"`
	Held        int       `json:"held"`
	Note        string    `json:"note,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// joinedJSON is an account an invite admitted: through a code or an email
// invite.
type joinedJSON struct {
	Source               string     `json:"source"` // "code" or "invite"
	PrincipalID          *uuid.UUID `json:"principal_id,omitempty"`
	Email                string     `json:"email"`
	JoinedAt             time.Time  `json:"joined_at"`
	CodeID               *uuid.UUID `json:"code_id,omitempty"`
	CodeKind             string     `json:"code_kind,omitempty"`
	CodeLabel            string     `json:"code_label,omitempty"`
	CodeHint             string     `json:"code_hint,omitempty"`
	InvitedByPrincipalID *uuid.UUID `json:"invited_by_principal_id,omitempty"`
	InvitedByLabel       string     `json:"invited_by_label,omitempty"`
}

// --- member routes ---

func (a *api) settings(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	isAdmin, err := a.o.IsAdmin(r.Context(), caller)
	if err != nil {
		a.internal(w, r, "checking platform administration", err)
		return
	}
	m := a.o.Codes.MemberOptions()
	writeJSON(w, http.StatusOK, map[string]any{
		"default_allowance":       m.DefaultAllowance,
		"member_code_ttl_seconds": int64(m.CodeTTL / time.Second),
		"signup_url":              a.o.SignupURL,
		"is_admin":                isAdmin,
	})
}

func (a *api) myInvites(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	sum, err := a.o.Codes.MemberInvites(r.Context(), caller)
	if err != nil {
		a.internal(w, r, "reading member invites", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"allowance":               sum.Allowance,
		"held":                    sum.Held,
		"remaining":               sum.Remaining,
		"member_code_ttl_seconds": int64(sum.CodeTTL / time.Second),
		"codes":                   toCodesJSON(sum.Codes, time.Now()),
	})
}

func (a *api) createMyCode(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	c, value, err := a.o.Codes.CreateMemberCode(r.Context(), caller)
	if errors.Is(err, signupgate.ErrAllowanceExhausted) {
		writeError(w, http.StatusConflict, "no invites left")
		return
	}
	if err != nil {
		a.internal(w, r, "creating a member code", err)
		return
	}
	a.emit(r.Context(), signupgate.EventCodeCreated, "create", caller,
		audit.Resource{Type: "signup_code", ID: c.ID}, map[string]any{"kind": string(c.Kind)})
	writeJSON(w, http.StatusCreated, a.created(c, value))
}

func (a *api) revokeMyCode(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such invite code")
		return
	}
	switch err := a.o.Codes.RevokeMemberCode(r.Context(), caller, id); {
	case errors.Is(err, signupgate.ErrCodeNotFound):
		writeError(w, http.StatusNotFound, "no such invite code")
		return
	case err != nil:
		a.internal(w, r, "revoking a member code", err)
		return
	}
	a.emit(r.Context(), signupgate.EventCodeRevoked, "revoke", caller, audit.Resource{Type: "signup_code", ID: id}, nil)
	a.writeCode(w, r, id)
}

// --- operator routes: email invites ---

func (a *api) listInvites(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	all := r.URL.Query().Get("status") == statusAll
	invites, err := a.o.Invites.List(r.Context(), all)
	if err != nil {
		a.internal(w, r, "listing invites", err)
		return
	}
	now := time.Now()
	out := make([]inviteJSON, 0, len(invites))
	for _, i := range invites {
		out = append(out, toInviteJSON(i, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

type addInvitesRequest struct {
	Emails        []string `json:"emails"`
	Note          string   `json:"note"`
	ExpiresInDays int      `json:"expires_in_days"`
}

func (r addInvitesRequest) validate() (*time.Time, error) {
	if len(r.Emails) == 0 || len(r.Emails) > maxEmailsPerCall {
		return nil, fmt.Errorf("give between 1 and %d email addresses", maxEmailsPerCall)
	}
	if len(r.Note) > 500 {
		return nil, errors.New("note is longer than 500 characters")
	}
	return expiry(r.ExpiresInDays)
}

func (a *api) addInvites(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	var req addInvitesRequest
	if !readJSON(w, r, &req) {
		return
	}
	exp, err := req.validate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now()
	var (
		created  []inviteJSON
		failures []map[string]string
	)
	for _, email := range req.Emails {
		inv, err := a.o.Invites.Add(r.Context(), email, signupgate.AddOptions{
			Note: req.Note, InvitedByPrincipal: &caller, ExpiresAt: exp,
		})
		switch {
		case errors.Is(err, signupgate.ErrInvalidEmail):
			failures = append(failures, map[string]string{"email": email, "error": "not a plain email address"})
			continue
		case errors.Is(err, signupgate.ErrAlreadyRedeemed):
			failures = append(failures, map[string]string{"email": email, "error": "already has an account from an invite"})
			continue
		case err != nil:
			a.internal(w, r, "adding an invite", err)
			return
		}
		a.emit(r.Context(), signupgate.EventInviteCreated, "create", caller,
			audit.Resource{Type: "signup_invite", Identifier: inv.Email}, nil)
		created = append(created, toInviteJSON(*inv, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": nonNil(created), "failed": nonNil(failures)})
}

func (a *api) revokeInvite(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	email := r.PathValue("email")
	switch err := a.o.Invites.Revoke(r.Context(), email); {
	case errors.Is(err, signupgate.ErrNotFound), errors.Is(err, signupgate.ErrInvalidEmail):
		writeError(w, http.StatusNotFound, "no invite for that address")
		return
	case err != nil:
		a.internal(w, r, "revoking an invite", err)
		return
	}
	a.emit(r.Context(), signupgate.EventInviteRevoked, "revoke", caller,
		audit.Resource{Type: "signup_invite", Identifier: email}, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- operator routes: codes ---

func (a *api) listCodes(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	q := r.URL.Query()
	f := signupgate.CodeFilter{Label: q.Get("label"), ActiveOnly: q.Get("status") == statusActive}
	switch kind := q.Get("kind"); kind {
	case "":
	case string(signupgate.CodeOperator), string(signupgate.CodeMember):
		f.Kind = signupgate.CodeKind(kind)
	default:
		writeError(w, http.StatusBadRequest, "kind is operator or member")
		return
	}
	codes, err := a.o.Codes.ListCodes(r.Context(), f)
	if err != nil {
		a.internal(w, r, "listing codes", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"codes": toCodesJSON(codes, time.Now())})
}

type createCodeRequest struct {
	Label         string `json:"label"`
	Note          string `json:"note"`
	MaxUses       int    `json:"max_uses"`
	ExpiresInDays int    `json:"expires_in_days"`
}

func (a *api) createCode(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	var req createCodeRequest
	if !readJSON(w, r, &req) {
		return
	}
	switch {
	case req.MaxUses < 1 || req.MaxUses > maxUsesPerCode:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("max_uses is between 1 and %d", maxUsesPerCode))
		return
	case len(req.Label) > 100:
		writeError(w, http.StatusBadRequest, "label is longer than 100 characters")
		return
	case len(req.Note) > 500:
		writeError(w, http.StatusBadRequest, "note is longer than 500 characters")
		return
	}
	exp, err := expiry(req.ExpiresInDays)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, value, err := a.o.Codes.CreateCode(r.Context(), signupgate.CodeOptions{
		Kind: signupgate.CodeOperator, Label: req.Label, Note: req.Note,
		CreatedByPrincipal: &caller, MaxUses: req.MaxUses, ExpiresAt: exp,
	})
	if err != nil {
		a.internal(w, r, "creating a code", err)
		return
	}
	a.emit(r.Context(), signupgate.EventCodeCreated, "create", caller, audit.Resource{Type: "signup_code", ID: c.ID},
		map[string]any{"kind": string(c.Kind), "label": c.Label, "max_uses": c.MaxUses})
	writeJSON(w, http.StatusCreated, a.created(c, value))
}

func (a *api) revokeCode(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "no such invite code")
		return
	}
	switch err := a.o.Codes.RevokeCode(r.Context(), id); {
	case errors.Is(err, signupgate.ErrCodeNotFound):
		writeError(w, http.StatusNotFound, "no such invite code")
		return
	case err != nil:
		a.internal(w, r, "revoking a code", err)
		return
	}
	a.emit(r.Context(), signupgate.EventCodeRevoked, "revoke", caller, audit.Resource{Type: "signup_code", ID: id}, nil)
	a.writeCode(w, r, id)
}

// --- operator routes: waitlist ---

func (a *api) listWaitlist(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	entries, err := a.o.Waitlist.List(r.Context())
	if err != nil {
		a.internal(w, r, "listing the waitlist", err)
		return
	}
	out := make([]waitlistJSON, 0, len(entries))
	for _, e := range entries {
		out = append(out, waitlistJSON{
			Email: e.Email, ConsentVersion: e.ConsentVersion, JoinedAt: e.CreatedAt,
			LastSubmittedAt: e.UpdatedAt, InvitedAt: e.InvitedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"waitlist": out})
}

func (a *api) inviteWaitlist(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	var req addInvitesRequest
	if !readJSON(w, r, &req) {
		return
	}
	exp, err := req.validate()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	invited, err := a.o.Waitlist.Invite(r.Context(), a.o.Invites, req.Emails, signupgate.AddOptions{
		Note: req.Note, InvitedByPrincipal: &caller, ExpiresAt: exp,
	})
	now := time.Now()
	out := make([]inviteJSON, 0, len(invited))
	for _, inv := range invited {
		a.emit(r.Context(), signupgate.EventWaitlistInvited, "invite", caller,
			audit.Resource{Type: "signup_waitlist", Identifier: inv.Email}, nil)
		out = append(out, toInviteJSON(inv, now))
	}
	resp := map[string]any{"invites": out}
	if err != nil {
		// Individual failures (not listed, already redeemed) are reported,
		// not treated as a server error.
		resp["error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *api) removeWaitlist(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	switch err := a.o.Waitlist.Remove(r.Context(), r.PathValue("email")); {
	case errors.Is(err, signupgate.ErrNotFound), errors.Is(err, signupgate.ErrInvalidEmail):
		writeError(w, http.StatusNotFound, "that address is not on the waitlist")
		return
	case err != nil:
		a.internal(w, r, "removing from the waitlist", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- operator routes: allowances and joined accounts ---

func (a *api) listAllowances(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	list, err := a.o.Codes.Allowances(r.Context())
	if err != nil {
		a.internal(w, r, "listing allowances", err)
		return
	}
	out := make([]allowanceJSON, 0, len(list))
	for _, al := range list {
		out = append(out, allowanceJSON{
			PrincipalID: al.PrincipalID, Email: al.Email, Granted: al.Granted, Effective: al.Effective,
			Held: al.Held, Note: al.Note, UpdatedAt: al.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"allowances": out})
}

type setAllowanceRequest struct {
	Email   string `json:"email"`
	Granted *int   `json:"granted"` // null returns the member to the default
	Note    string `json:"note"`
}

func (a *api) setAllowance(w http.ResponseWriter, r *http.Request, caller uuid.UUID) {
	var req setAllowanceRequest
	if !readJSON(w, r, &req) {
		return
	}
	if req.Granted != nil && *req.Granted < 0 {
		writeError(w, http.StatusBadRequest, "granted cannot be negative")
		return
	}
	if len(req.Note) > 500 {
		writeError(w, http.StatusBadRequest, "note is longer than 500 characters")
		return
	}
	member, err := a.o.Codes.PrincipalByEmail(r.Context(), req.Email)
	switch {
	case errors.Is(err, signupgate.ErrNoAccount), errors.Is(err, signupgate.ErrInvalidEmail):
		writeError(w, http.StatusNotFound, "no account with that email address")
		return
	case err != nil:
		a.internal(w, r, "finding the member", err)
		return
	}
	if err := a.o.Codes.SetAllowance(r.Context(), member, req.Granted, req.Note, &caller); err != nil {
		a.internal(w, r, "setting the allowance", err)
		return
	}
	details := map[string]any{"granted": nil}
	if req.Granted != nil {
		details["granted"] = *req.Granted
	}
	a.emit(r.Context(), signupgate.EventAllowanceSet, "set", caller, audit.Resource{Type: "principal", ID: member}, details)
	sum, err := a.o.Codes.MemberInvites(r.Context(), member)
	if err != nil {
		a.internal(w, r, "reading the allowance", err)
		return
	}
	writeJSON(w, http.StatusOK, allowanceJSON{
		PrincipalID: member, Email: req.Email, Granted: req.Granted, Effective: sum.Allowance,
		Held: sum.Held, Note: req.Note, UpdatedAt: time.Now(),
	})
}

// joined lists the accounts invites admitted, newest first. Filters:
// code_id and label keep code redemptions only; inviter keeps accounts a
// person invited, by code or by email invite.
func (a *api) joined(w http.ResponseWriter, r *http.Request, _ uuid.UUID) {
	q := r.URL.Query()
	var f signupgate.RedemptionFilter
	if v := q.Get("code_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "code_id is not an ID")
			return
		}
		f.CodeID = &id
	}
	if v := q.Get("inviter"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "inviter is not an ID")
			return
		}
		f.CreatedBy = &id
	}
	f.Label = q.Get("label")
	reds, err := a.o.Codes.Redemptions(r.Context(), f)
	if err != nil {
		a.internal(w, r, "listing redemptions", err)
		return
	}
	out := make([]joinedJSON, 0, len(reds))
	for _, rd := range reds {
		pid, cid := rd.PrincipalID, rd.CodeID
		out = append(out, joinedJSON{
			Source: "code", PrincipalID: &pid, Email: rd.Email, JoinedAt: rd.CreatedAt, CodeID: &cid,
			CodeKind: string(rd.CodeKind), CodeLabel: rd.CodeLabel, CodeHint: rd.CodeHint,
			InvitedByPrincipalID: rd.CodeCreatedBy, InvitedByLabel: rd.CodeCreatedByLabel,
		})
	}
	if f.CodeID == nil && f.Label == "" {
		invites, err := a.o.Invites.List(r.Context(), true)
		if err != nil {
			a.internal(w, r, "listing invites", err)
			return
		}
		for _, inv := range invites {
			if inv.RedeemedAt == nil {
				continue
			}
			if f.CreatedBy != nil && (inv.InvitedByPrincipal == nil || *inv.InvitedByPrincipal != *f.CreatedBy) {
				continue
			}
			out = append(out, joinedJSON{
				Source: "invite", PrincipalID: inv.RedeemedBy, Email: inv.Email, JoinedAt: *inv.RedeemedAt,
				InvitedByPrincipalID: inv.InvitedByPrincipal, InvitedByLabel: inv.InvitedBy,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].JoinedAt.After(out[j].JoinedAt) })
	writeJSON(w, http.StatusOK, map[string]any{"joined": out})
}

// --- helpers ---

func (a *api) created(c signupgate.Code, value string) createdCodeJSON {
	out := createdCodeJSON{Code: toCodeJSON(c, time.Now()), InviteCode: value}
	if a.o.SignupURL != "" {
		out.Link = signupgate.CodeLink(a.o.SignupURL, value)
	}
	return out
}

func (a *api) writeCode(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	c, err := a.o.Codes.GetCode(r.Context(), id)
	if err != nil {
		a.internal(w, r, "reading a code", err)
		return
	}
	writeJSON(w, http.StatusOK, toCodeJSON(c, time.Now()))
}

func expiry(days int) (*time.Time, error) {
	if days < 0 || days > maxExpiresInDays {
		return nil, fmt.Errorf("expires_in_days is between 0 (never) and %d", maxExpiresInDays)
	}
	if days == 0 {
		return nil, nil
	}
	t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
	return &t, nil
}

func (a *api) emit(ctx context.Context, eventType, action string, actor uuid.UUID, res audit.Resource, details map[string]any) {
	if a.o.Audit == nil {
		return
	}
	ev := &audit.Event{
		EventType: eventType, Action: action,
		Actor:    audit.Actor{ID: actor, Type: "human"},
		Resource: res, Outcome: "success", Details: details,
	}
	if err := a.o.Audit.Emit(ctx, ev); err != nil {
		a.o.Logger.ErrorContext(ctx, "signupapi: emit audit event", "event_type", eventType, "error", err)
	}
}

func (a *api) internal(w http.ResponseWriter, r *http.Request, what string, err error) {
	a.o.Logger.ErrorContext(r.Context(), "signupapi: "+what, "error", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// The status is sent; the client sees a truncated body.
		slog.Default().Error("signupapi: writing a response", "error", err)
	}
}
