// Package mpclient calls the managed-principal API that SystemAuth serves to
// relying parties (systemauthsvc.ManagedPrincipalsPath). Every call acts as
// the signed-in manager and takes that manager's SystemAuth access token,
// granted the systemforge:managed_principals scope; the API takes the
// application from the token's client.
//
// SystemAuth binds the tokens it issues to the requesting client's DPoP key
// and accepts a bound token only with a proof by that key, so a Client that
// sends a relying party's session tokens needs an http.Client whose
// Transport is that relying party's relyingparty.Client.Transport. The
// Client sets the token as Bearer, and the transport presents it with the
// DPoP scheme and a proof. Without it, SystemAuth answers ErrUnauthorized.
//
// The package depends on the standard library and uuid only, so an
// application in another process does not import SystemAuth's storage.
package mpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Errors an API call can return, each wrapped in an *APIError.
var (
	// ErrUnauthorized means the access token is missing, invalid or expired.
	ErrUnauthorized = errors.New("mpclient: unauthorized")
	// ErrForbidden means the manager may not do this, the principal does not
	// exist or is not theirs, or the token lacks the scope. The API gives one
	// answer for all of these.
	ErrForbidden = errors.New("mpclient: forbidden")
	// ErrNotFound means the route or a token, session or invitation was not
	// found.
	ErrNotFound = errors.New("mpclient: not found")
	// ErrInvalidCode means a claim code or invitation token cannot be used,
	// for any reason.
	ErrInvalidCode = errors.New("mpclient: invalid code")
	// ErrInvalidRequest means the request was refused as malformed or
	// incomplete; APIError.Message says why.
	ErrInvalidRequest = errors.New("mpclient: invalid request")
	// ErrConflict means the request conflicts with the principal's state,
	// such as removing its last manager.
	ErrConflict = errors.New("mpclient: conflict")
	// ErrRateLimited means too many attempts; APIError.RetryAfter says when
	// to try again.
	ErrRateLimited = errors.New("mpclient: rate limited")
)

// APIError is an unsuccessful response.
type APIError struct {
	Status     int
	Message    string
	RetryAfter time.Duration
	kind       error
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("mpclient: HTTP %d", e.Status)
	}
	return fmt.Sprintf("mpclient: HTTP %d: %s", e.Status, e.Message)
}

// Unwrap returns the Err* value matching the status, or nil.
func (e *APIError) Unwrap() error { return e.kind }

// Roles a manager can hold. Deployments may register further roles.
const (
	RoleGuardian = "guardian"
	RoleEducator = "educator"
)

// ManagedPrincipal is a managed principal as its manager lists it.
type ManagedPrincipal struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	DisplayName string    `json:"display_name"`
	// Roles are the roles the calling manager holds over it.
	Roles []string `json:"roles"`
}

// Manager is a manager relationship.
type Manager struct {
	PrincipalID uuid.UUID `json:"principal_id"`
	Role        string    `json:"role"`
}

// CreateInput describes a managed principal to create. The caller becomes
// its manager in Role.
type CreateInput struct {
	DisplayName string
	// Email optionally gives the principal an unverified address.
	Email string
	Role  string
}

// IssueLoginTokenInput describes a login token to issue.
type IssueLoginTokenInput struct {
	// Name optionally labels the token, such as the card or device.
	Name string `json:"name,omitempty"`
	// SingleUse makes the token valid for one sign-in.
	SingleUse bool `json:"single_use,omitempty"`
	// ExpiresAt optionally sets the expiry; the server clamps it to its
	// ceiling. Nil uses the client's or the deployment's default.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// IssuedLoginToken is a newly issued login token. Token is returned only
// once; render it as a code or card and do not store it.
type IssuedLoginToken struct {
	ID        uuid.UUID  `json:"id"`
	Token     string     `json:"token"`
	Prefix    string     `json:"prefix"`
	SingleUse bool       `json:"single_use"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// LoginToken is a live login token, without its value.
type LoginToken struct {
	ID         uuid.UUID  `json:"id"`
	Prefix     string     `json:"prefix"`
	Name       string     `json:"name,omitempty"`
	IssuedBy   uuid.UUID  `json:"issued_by"`
	SingleUse  bool       `json:"single_use"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP string     `json:"last_used_ip,omitempty"`
}

// Session is one way a managed principal is signed in. Kind is "login",
// "oauth" or "principal_token".
type Session struct {
	ID         uuid.UUID  `json:"id"`
	Kind       string     `json:"kind"`
	Provider   string     `json:"provider,omitempty"`
	ClientID   string     `json:"client_id,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ClientIP   string     `json:"client_ip,omitempty"`
}

// Claim is a single-use code that lets another person become a guardian.
type Claim struct {
	ID        uuid.UUID `json:"id"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Invitation is an offer to manage a person with a verified address.
type Invitation struct {
	ID        uuid.UUID `json:"id"`
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Client calls the managed-principal API.
type Client struct {
	base string
	hc   *http.Client
}

// New returns a Client for the API at baseURL, such as
// "https://auth.example.com/managed-principals". A nil hc uses
// http.DefaultClient. For DPoP-bound tokens, give hc the relying party's
// transport:
//
//	mp := mpclient.New(base, &http.Client{Transport: rp.Transport(nil)})
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), hc: hc}
}

// Create creates a managed principal with the caller as its only manager
// and returns its ID.
func (c *Client) Create(ctx context.Context, token string, in CreateInput) (uuid.UUID, error) {
	body := struct {
		DisplayName string `json:"display_name"`
		Email       string `json:"email,omitempty"`
		Role        string `json:"role"`
	}{DisplayName: in.DisplayName, Email: in.Email, Role: in.Role}
	var out struct {
		ID uuid.UUID `json:"id"`
	}
	if err := c.do(ctx, token, http.MethodPost, "/", body, &out); err != nil {
		return uuid.Nil, err
	}
	return out.ID, nil
}

// List returns a page of the caller's managed principals in principal-ID
// order, after the given ID (uuid.Nil for the first page). A short or empty
// page is the last. limit 0 uses the server's maximum.
func (c *Client) List(ctx context.Context, token string, after uuid.UUID, limit int) ([]ManagedPrincipal, error) {
	q := url.Values{}
	if after != uuid.Nil {
		q.Set("after", after.String())
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out struct {
		Managed []ManagedPrincipal `json:"managed_principals"`
	}
	if err := c.do(ctx, token, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out.Managed, nil
}

// IssueLoginToken issues a login token for a managed principal.
func (c *Client) IssueLoginToken(ctx context.Context, token string, id uuid.UUID, in IssueLoginTokenInput) (*IssuedLoginToken, error) {
	var out IssuedLoginToken
	if err := c.do(ctx, token, http.MethodPost, "/"+id.String()+"/login-tokens", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListLoginTokens returns a managed principal's live login tokens.
func (c *Client) ListLoginTokens(ctx context.Context, token string, id uuid.UUID) ([]LoginToken, error) {
	var out struct {
		Tokens []LoginToken `json:"login_tokens"`
	}
	if err := c.do(ctx, token, http.MethodGet, "/"+id.String()+"/login-tokens", nil, &out); err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

// RevokeLoginToken revokes one login token.
func (c *Client) RevokeLoginToken(ctx context.Context, token string, id, credentialID uuid.UUID) error {
	return c.do(ctx, token, http.MethodDelete, "/"+id.String()+"/login-tokens/"+credentialID.String(), nil, nil)
}

// ListSessions returns the ways a managed principal is signed in.
func (c *Client) ListSessions(ctx context.Context, token string, id uuid.UUID) ([]Session, error) {
	var out struct {
		Sessions []Session `json:"sessions"`
	}
	if err := c.do(ctx, token, http.MethodGet, "/"+id.String()+"/sessions", nil, &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}

// RevokeSession ends one session of the given kind.
func (c *Client) RevokeSession(ctx context.Context, token string, id uuid.UUID, kind string, sessionID uuid.UUID) error {
	return c.do(ctx, token, http.MethodDelete, "/"+id.String()+"/sessions/"+url.PathEscape(kind)+"/"+sessionID.String(), nil, nil)
}

// RevokeAll revokes every login token and session of a managed principal.
func (c *Client) RevokeAll(ctx context.Context, token string, id uuid.UUID) error {
	return c.do(ctx, token, http.MethodPost, "/"+id.String()+"/revoke-all", nil, nil)
}

// ListManagers returns a managed principal's active managers.
func (c *Client) ListManagers(ctx context.Context, token string, id uuid.UUID) ([]Manager, error) {
	var out struct {
		Managers []Manager `json:"managers"`
	}
	if err := c.do(ctx, token, http.MethodGet, "/"+id.String()+"/managers", nil, &out); err != nil {
		return nil, err
	}
	return out.Managers, nil
}

// RemoveManager ends a manager's role over a managed principal. The last
// manager of a principal without a verified email cannot be removed.
func (c *Client) RemoveManager(ctx context.Context, token string, id, managerID uuid.UUID, role string) error {
	return c.do(ctx, token, http.MethodDelete, "/"+id.String()+"/managers/"+managerID.String()+"/"+url.PathEscape(role), nil, nil)
}

// Release ends management of a principal that has a verified email.
func (c *Client) Release(ctx context.Context, token string, id uuid.UUID) error {
	return c.do(ctx, token, http.MethodPost, "/"+id.String()+"/release", nil, nil)
}

// Delete deletes a managed principal.
func (c *Client) Delete(ctx context.Context, token string, id uuid.UUID) error {
	return c.do(ctx, token, http.MethodDelete, "/"+id.String(), nil, nil)
}

// IssueClaim issues a single-use claim code for a managed principal.
func (c *Client) IssueClaim(ctx context.Context, token string, id uuid.UUID) (*Claim, error) {
	var out Claim
	if err := c.do(ctx, token, http.MethodPost, "/"+id.String()+"/claims", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RedeemClaim redeems a claim code: the caller becomes a guardian of the
// principal it names, whose ID is returned.
func (c *Client) RedeemClaim(ctx context.Context, token, code string) (uuid.UUID, error) {
	var out struct {
		PrincipalID uuid.UUID `json:"principal_id"`
	}
	if err := c.do(ctx, token, http.MethodPost, "/claims/redeem", map[string]string{"code": code}, &out); err != nil {
		return uuid.Nil, err
	}
	return out.PrincipalID, nil
}

// InviteManager offers to manage the person with a verified address, in
// role.
func (c *Client) InviteManager(ctx context.Context, token, email, role string) (*Invitation, error) {
	var out Invitation
	if err := c.do(ctx, token, http.MethodPost, "/manager-invites", map[string]string{"email": email, "role": role}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// AcceptInvitation accepts an invitation to be managed and returns the new
// manager's ID.
func (c *Client) AcceptInvitation(ctx context.Context, token, invitation string) (uuid.UUID, error) {
	var out struct {
		ManagerPrincipalID uuid.UUID `json:"manager_principal_id"`
	}
	if err := c.do(ctx, token, http.MethodPost, "/manager-invites/accept", map[string]string{"token": invitation}, &out); err != nil {
		return uuid.Nil, err
	}
	return out.ManagerPrincipalID, nil
}

// DeclineInvitation declines an invitation to be managed.
func (c *Client) DeclineInvitation(ctx context.Context, token, invitation string) error {
	return c.do(ctx, token, http.MethodPost, "/manager-invites/decline", map[string]string{"token": invitation}, nil)
}

// RevokeInvitation withdraws an invitation the caller made.
func (c *Client) RevokeInvitation(ctx context.Context, token string, invitationID uuid.UUID) error {
	return c.do(ctx, token, http.MethodDelete, "/manager-invites/"+invitationID.String(), nil, nil)
}

// maxResponseBytes bounds the responses the client reads.
const maxResponseBytes = 1 << 20

func (c *Client) do(ctx context.Context, token, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("mpclient: encode request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rdr)
	if err != nil {
		return fmt.Errorf("mpclient: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("mpclient: %s %s: %w", method, path, err)
	}
	data, readErr := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if cerr := resp.Body.Close(); cerr != nil && readErr == nil {
		readErr = cerr
	}
	if readErr != nil {
		return fmt.Errorf("mpclient: read response: %w", readErr)
	}
	if resp.StatusCode >= 300 {
		return apiError(resp, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("mpclient: decode response: %w", err)
	}
	return nil
}

func apiError(resp *http.Response, data []byte) *APIError {
	e := &APIError{Status: resp.StatusCode}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &body) == nil {
		e.Message = body.Error
		if e.Message == "" {
			e.Message = body.Message
		}
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		e.kind = ErrUnauthorized
	case http.StatusForbidden:
		e.kind = ErrForbidden
	case http.StatusNotFound:
		e.kind = ErrNotFound
	case http.StatusConflict:
		e.kind = ErrConflict
	case http.StatusTooManyRequests:
		e.kind = ErrRateLimited
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			e.RetryAfter = time.Duration(s) * time.Second
		}
	case http.StatusBadRequest:
		e.kind = ErrInvalidRequest
		if e.Message == "invalid code" {
			e.kind = ErrInvalidCode
		}
	}
	return e
}
