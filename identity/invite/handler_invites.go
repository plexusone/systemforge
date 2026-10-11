package invite

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/organization"
)

// InviteResponse is the API representation of an invite.
type InviteResponse struct {
	ID                    string            `json:"id"`
	OrganizationID        string            `json:"organization_id"`
	InviterPrincipalID    string            `json:"inviter_principal_id"`
	Email                 string            `json:"email"`
	Role                  string            `json:"role"`
	AppRoles              map[string]string `json:"app_roles,omitempty"`
	Status                string            `json:"status"`
	Message               *string           `json:"message,omitempty"`
	ExpiresAt             time.Time         `json:"expires_at"`
	AcceptedAt            *time.Time        `json:"accepted_at,omitempty"`
	AcceptedByPrincipalID *string           `json:"accepted_by_principal_id,omitempty"`
	ResendCount           int               `json:"resend_count"`
	LastSentAt            time.Time         `json:"last_sent_at"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// InviteResultResponse includes the invite URL.
type InviteResultResponse struct {
	Invite    *InviteResponse `json:"invite"`
	InviteURL string          `json:"invite_url"`
}

func inviteToResponse(inv *Invite) *InviteResponse {
	resp := &InviteResponse{
		ID:                 inv.ID.String(),
		OrganizationID:     inv.OrganizationID.String(),
		InviterPrincipalID: inv.InviterPrincipalID.String(),
		Email:              inv.Email,
		Role:               inv.Role,
		AppRoles:           inv.AppRoles,
		Status:             string(inv.Status),
		Message:            inv.Message,
		ExpiresAt:          inv.ExpiresAt,
		AcceptedAt:         inv.AcceptedAt,
		ResendCount:        inv.ResendCount,
		LastSentAt:         inv.LastSentAt,
		CreatedAt:          inv.CreatedAt,
		UpdatedAt:          inv.UpdatedAt,
	}
	if inv.AcceptedByPrincipalID != nil {
		s := inv.AcceptedByPrincipalID.String()
		resp.AcceptedByPrincipalID = &s
	}
	return resp
}

func inviteResultToResponse(result *InviteResult) *InviteResultResponse {
	return &InviteResultResponse{
		Invite:    inviteToResponse(result.Invite),
		InviteURL: result.InviteURL,
	}
}

// CreateInviteRequest is the request for creating an invite.
type CreateInviteRequest struct {
	Slug string `path:"slug"`
	Body struct {
		Email              string            `json:"email" required:"true" format:"email"`
		Role               string            `json:"role" required:"true" enum:"owner,admin,member,collaborator"`
		AppRoles           map[string]string `json:"app_roles,omitempty" doc:"Application roles to grant on acceptance, application identifier to role; none is preselected"`
		Message            *string           `json:"message,omitempty"`
		InviterPrincipalID string            `json:"inviter_principal_id,omitempty" required:"false" format:"uuid" doc:"Deprecated: the inviter is the authenticated caller; when present it must equal the caller"`
		ExpiresInHours     int               `json:"expires_in_hours,omitempty" minimum:"1" maximum:"720"`
	}
}

// CreateInviteResponse is the response for creating an invite.
type CreateInviteResponse struct {
	Body *InviteResultResponse
}

// GetInviteByTokenRequest is the request for getting an invite by token.
type GetInviteByTokenRequest struct {
	Token string `path:"token"`
}

// GetInviteByTokenResponse is the response for getting an invite.
type GetInviteByTokenResponse struct {
	Body *InviteResponse
}

// AcceptInviteRequest is the request for accepting an invite.
type AcceptInviteRequest struct {
	Token string `path:"token"`
	Body  struct {
		PrincipalID string `json:"principal_id,omitempty" required:"false" format:"uuid" doc:"Deprecated: the accepting principal is the authenticated caller; when present it must equal the caller"`
	}
}

// AcceptInviteResponse is the response for accepting an invite.
type AcceptInviteResponse struct {
	Body *InviteResponse
}

// DeclineInviteRequest is the request for declining an invite.
type DeclineInviteRequest struct {
	Token string `path:"token"`
}

// DeclineInviteResponse is the response for declining an invite.
type DeclineInviteResponse struct {
	Body *InviteResponse
}

// RevokeInviteRequest is the request for revoking an invite.
type RevokeInviteRequest struct {
	Slug     string `path:"slug"`
	InviteID string `path:"invite_id" format:"uuid"`
}

// ResendInviteRequest is the request for resending an invite.
type ResendInviteRequest struct {
	Slug     string `path:"slug"`
	InviteID string `path:"invite_id" format:"uuid"`
}

// ResendInviteResponse is the response for resending an invite.
type ResendInviteResponse struct {
	Body *InviteResultResponse
}

// ListInvitesRequest is the request for listing invites.
type ListInvitesRequest struct {
	Slug string `path:"slug"`
	// Huma does not support pointer parameters; empty lists every status.
	Status string `query:"status" enum:"pending,accepted,declined,expired,revoked"`
	Limit  int    `query:"limit" default:"20" minimum:"1" maximum:"100"`
	Offset int    `query:"offset" default:"0" minimum:"0"`
}

// ListInvitesResponse is the response for listing invites.
type ListInvitesResponse struct {
	Body struct {
		Invites []*InviteResponse `json:"invites"`
	}
}

// ListPendingInvitesForEmailRequest is the request for listing pending invites by email.
type ListPendingInvitesForEmailRequest struct {
	// Email is deprecated: the invites listed are the caller's. When
	// present it must be the caller's email.
	Email string `query:"email" format:"email" doc:"Deprecated: invites are listed for the authenticated caller's email; when present it must match"`
}

// ListPendingInvitesForEmailResponse is the response for listing pending invites.
type ListPendingInvitesForEmailResponse struct {
	Body struct {
		Invites []*InviteResponse `json:"invites"`
	}
}

// registerInviteEndpoints registers invite management endpoints.
func (a *API) registerInviteEndpoints() {
	basePath := a.config.BasePath

	// Create Invite (under organization)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "createInvite",
		Method:        http.MethodPost,
		Path:          basePath + "/organizations/{slug}/invites",
		Summary:       "Create an invite",
		Description:   "Creates a new invitation to join an organization",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusCreated,
	}, a.createInvite)

	// List Invites for Organization
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listInvites",
		Method:        http.MethodGet,
		Path:          basePath + "/organizations/{slug}/invites",
		Summary:       "List invites",
		Description:   "Returns all invites for an organization",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.listInvites)

	// Revoke Invite
	huma.Register(a.huma, huma.Operation{
		OperationID:   "revokeInvite",
		Method:        http.MethodDelete,
		Path:          basePath + "/organizations/{slug}/invites/{invite_id}",
		Summary:       "Revoke an invite",
		Description:   "Revokes a pending invitation",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusNoContent,
	}, a.revokeInvite)

	// Resend Invite
	huma.Register(a.huma, huma.Operation{
		OperationID:   "resendInvite",
		Method:        http.MethodPost,
		Path:          basePath + "/organizations/{slug}/invites/{invite_id}/resend",
		Summary:       "Resend an invite",
		Description:   "Resends an invitation with a new token",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.resendInvite)

	// Get Invite by Token (public endpoint for invite links)
	huma.Register(a.huma, huma.Operation{
		OperationID:   "getInviteByToken",
		Method:        http.MethodGet,
		Path:          basePath + "/invites/{token}",
		Summary:       "Get invite by token",
		Description:   "Returns invite details by token (for invite link landing page)",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.getInviteByToken)

	// Accept Invite
	huma.Register(a.huma, huma.Operation{
		OperationID:   "acceptInvite",
		Method:        http.MethodPost,
		Path:          basePath + "/invites/{token}/accept",
		Summary:       "Accept an invite",
		Description:   "Accepts an invitation and joins the organization",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.acceptInvite)

	// Decline Invite
	huma.Register(a.huma, huma.Operation{
		OperationID:   "declineInvite",
		Method:        http.MethodPost,
		Path:          basePath + "/invites/{token}/decline",
		Summary:       "Decline an invite",
		Description:   "Declines an invitation",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.declineInvite)

	// List Pending Invites for Email
	huma.Register(a.huma, huma.Operation{
		OperationID:   "listPendingInvitesForEmail",
		Method:        http.MethodGet,
		Path:          basePath + "/invites",
		Summary:       "List pending invites for email",
		Description:   "Returns all pending invites for an email address",
		Tags:          []string{"Invites"},
		DefaultStatus: http.StatusOK,
	}, a.listPendingInvitesForEmail)
}

func (a *API) createInvite(ctx context.Context, input *CreateInviteRequest) (*CreateInviteResponse, error) {
	org, inviterID, err := a.orgForInvites(ctx, input.Slug)
	if err != nil {
		return nil, err
	}
	if input.Body.InviterPrincipalID != "" {
		claimed, err := uuid.Parse(input.Body.InviterPrincipalID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid inviter_principal_id")
		}
		if claimed != inviterID {
			return nil, huma.Error403Forbidden("inviter_principal_id must be the authenticated caller")
		}
	}
	// Inviting an owner needs owner rights.
	if input.Body.Role == organization.RoleOwner {
		ok, err := a.can(ctx, inviterID, org.ID, authz.PermOrgDelete)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, huma.Error403Forbidden("only an owner may invite an owner")
		}
	}

	expiresIn := DefaultInviteExpiry
	if input.Body.ExpiresInHours > 0 {
		expiresIn = time.Duration(input.Body.ExpiresInHours) * time.Hour
	}

	result, err := a.service.Create(ctx, CreateInviteInput{
		OrganizationID:     org.ID,
		InviterPrincipalID: inviterID,
		Email:              input.Body.Email,
		Role:               input.Body.Role,
		AppRoles:           input.Body.AppRoles,
		Message:            input.Body.Message,
		ExpiresIn:          expiresIn,
	})
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &CreateInviteResponse{Body: inviteResultToResponse(result)}, nil
}

func (a *API) listInvites(ctx context.Context, input *ListInvitesRequest) (*ListInvitesResponse, error) {
	org, _, err := a.orgForInvites(ctx, input.Slug)
	if err != nil {
		return nil, err
	}

	var status *Status
	if input.Status != "" {
		s := Status(input.Status)
		status = &s
	}

	invites, err := a.service.List(ctx, ListInvitesInput{
		OrganizationID: &org.ID,
		Status:         status,
		Limit:          input.Limit,
		Offset:         input.Offset,
	})
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	responses := make([]*InviteResponse, len(invites))
	for i, inv := range invites {
		responses[i] = inviteToResponse(inv)
	}

	output := &ListInvitesResponse{}
	output.Body.Invites = responses

	return output, nil
}

func (a *API) revokeInvite(ctx context.Context, input *RevokeInviteRequest) (*struct{}, error) {
	org, _, err := a.orgForInvites(ctx, input.Slug)
	if err != nil {
		return nil, err
	}
	inviteID, err := a.inviteInOrg(ctx, input.InviteID, org)
	if err != nil {
		return nil, err
	}

	if err := a.service.Revoke(ctx, inviteID); err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return nil, nil
}

func (a *API) resendInvite(ctx context.Context, input *ResendInviteRequest) (*ResendInviteResponse, error) {
	org, _, err := a.orgForInvites(ctx, input.Slug)
	if err != nil {
		return nil, err
	}
	inviteID, err := a.inviteInOrg(ctx, input.InviteID, org)
	if err != nil {
		return nil, err
	}

	result, err := a.service.Resend(ctx, inviteID)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &ResendInviteResponse{Body: inviteResultToResponse(result)}, nil
}

func (a *API) getInviteByToken(ctx context.Context, input *GetInviteByTokenRequest) (*GetInviteByTokenResponse, error) {
	invite, err := a.service.GetByToken(ctx, input.Token)
	if err != nil {
		return nil, huma.Error404NotFound(err.Error())
	}

	return &GetInviteByTokenResponse{Body: inviteToResponse(invite)}, nil
}

func (a *API) acceptInvite(ctx context.Context, input *AcceptInviteRequest) (*AcceptInviteResponse, error) {
	// The invite joins the caller, and only when addressed to its email.
	principalID, err := a.callerForInvite(ctx, input.Token)
	if err != nil {
		return nil, err
	}
	if input.Body.PrincipalID != "" {
		claimed, err := uuid.Parse(input.Body.PrincipalID)
		if err != nil {
			return nil, huma.Error400BadRequest("invalid principal_id")
		}
		if claimed != principalID {
			return nil, huma.Error403Forbidden("principal_id must be the authenticated caller")
		}
	}

	invite, err := a.service.Accept(ctx, AcceptInviteInput{
		Token:       input.Token,
		PrincipalID: principalID,
	})
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &AcceptInviteResponse{Body: inviteToResponse(invite)}, nil
}

func (a *API) declineInvite(ctx context.Context, input *DeclineInviteRequest) (*DeclineInviteResponse, error) {
	if _, err := a.callerForInvite(ctx, input.Token); err != nil {
		return nil, err
	}
	invite, err := a.service.Decline(ctx, input.Token)
	if err != nil {
		return nil, huma.Error400BadRequest(err.Error())
	}

	return &DeclineInviteResponse{Body: inviteToResponse(invite)}, nil
}

func (a *API) listPendingInvitesForEmail(ctx context.Context, input *ListPendingInvitesForEmailRequest) (*ListPendingInvitesForEmailResponse, error) {
	_, email, err := a.callerEmail(ctx)
	if err != nil {
		return nil, err
	}
	if input.Email != "" && !strings.EqualFold(input.Email, email) {
		return nil, huma.Error403Forbidden("invites can be listed only for your own email")
	}
	invites, err := a.service.ListPendingForEmail(ctx, email)
	if err != nil {
		return nil, huma.Error500InternalServerError(err.Error())
	}

	responses := make([]*InviteResponse, len(invites))
	for i, inv := range invites {
		responses[i] = inviteToResponse(inv)
	}

	output := &ListPendingInvitesForEmailResponse{}
	output.Body.Invites = responses

	return output, nil
}
