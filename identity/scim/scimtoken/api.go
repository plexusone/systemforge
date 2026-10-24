package scimtoken

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	orgsvc "github.com/plexusone/systemforge/identity/organization"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// SlugResolver finds an organization by its slug; organization.Service
// implements it.
type SlugResolver interface {
	ResolveSlug(ctx context.Context, slug string) (*orgsvc.Organization, bool, error)
}

// APIConfig configures the token management API.
type APIConfig struct {
	// BasePath prefixes every endpoint (default: "/api/v1"), matching the
	// organization API's, so the endpoints sit under
	// {BasePath}/organizations/{slug}/scim-tokens.
	BasePath string
	// Organizations resolves the organization slug in the path. Required.
	Organizations SlugResolver
	// Caller identifies the authenticated principal (default:
	// requestprincipal.PrincipalUUID, set by requestprincipal.Middleware).
	Caller func(ctx context.Context) (uuid.UUID, error)
	// Logger is the logger (default: slog.Default()).
	Logger *slog.Logger
}

// API serves token management over HTTP: list, issue, rotate and revoke
// an organization's SCIM tokens. The Service decides who may call it.
type API struct {
	service *Service
	config  APIConfig
	router  chi.Router
}

// NewAPI returns the token management API. Mount it beside the
// organization API, behind the same authentication middleware.
func NewAPI(service *Service, config APIConfig) (*API, error) {
	if service == nil {
		return nil, errors.New("scimtoken: NewAPI needs a Service")
	}
	if config.Organizations == nil {
		return nil, errors.New("scimtoken: APIConfig.Organizations is required")
	}
	if config.BasePath == "" {
		config.BasePath = "/api/v1"
	}
	if config.Caller == nil {
		config.Caller = requestprincipal.PrincipalUUID
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	a := &API{service: service, config: config}
	router := chi.NewRouter()
	router.Use(middleware.Recoverer)
	router.Use(noStore)
	hc := huma.DefaultConfig("SCIM Token API", "1.0")
	hc.Info.Description = "Issue, rotate and revoke an organization's SCIM bearer tokens"
	a.register(humachi.New(router, hc))
	a.router = router
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.router.ServeHTTP(w, r) }

// Router returns the API's router.
func (a *API) Router() chi.Router { return a.router }

// noStore keeps token responses, which may carry a plaintext token, out
// of caches.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// SlugInput names the organization.
type SlugInput struct {
	Slug string `path:"slug" doc:"Organization slug"`
}

// IssueInput is the body of an issue or rotate request.
type IssueInput struct {
	Slug string `path:"slug" doc:"Organization slug"`
	Body struct {
		Description      string `json:"description,omitempty" maxLength:"255" doc:"Optional note, such as the identity provider"`
		ExpiresInSeconds int64  `json:"expires_in_seconds,omitempty" minimum:"0" doc:"Lifetime in seconds; 0 or absent means no expiry"`
	}
}

// IssueOutput carries the new token, shown only once.
type IssueOutput struct {
	Body *Issued
}

// ListOutput lists an organization's tokens.
type ListOutput struct {
	Body struct {
		Tokens []Token `json:"tokens"`
	}
}

// RevokeInput names the token to revoke.
type RevokeInput struct {
	Slug    string `path:"slug" doc:"Organization slug"`
	TokenID string `path:"token_id" format:"uuid" doc:"Token ID"`
}

//nolint:dupl // Huma endpoint registration boilerplate
func (a *API) register(api huma.API) {
	base := a.config.BasePath + "/organizations/{slug}/scim-tokens"
	tags := []string{"SCIM Tokens"}
	huma.Register(api, huma.Operation{
		OperationID: "listScimTokens", Method: http.MethodGet, Path: base,
		Summary: "List SCIM tokens", Tags: tags, DefaultStatus: http.StatusOK,
	}, a.list)
	huma.Register(api, huma.Operation{
		OperationID: "issueScimToken", Method: http.MethodPost, Path: base,
		Summary:     "Issue the first SCIM token",
		Description: "Issues the organization's first SCIM token. Fails with 409 when a valid token exists; rotate instead.",
		Tags:        tags, DefaultStatus: http.StatusCreated,
	}, a.issue)
	huma.Register(api, huma.Operation{
		OperationID: "rotateScimToken", Method: http.MethodPost, Path: base + "/rotate",
		Summary:     "Rotate the SCIM token",
		Description: "Issues a new current token, keeps the previous one valid, and revokes older tokens.",
		Tags:        tags, DefaultStatus: http.StatusCreated,
	}, a.rotate)
	huma.Register(api, huma.Operation{
		OperationID: "revokeScimToken", Method: http.MethodDelete, Path: base + "/{token_id}",
		Summary:     "Revoke a SCIM token",
		Description: "Revokes a token. Revoking the current token makes the previous one current.",
		Tags:        tags, DefaultStatus: http.StatusNoContent,
	}, a.revoke)
}

func (a *API) list(ctx context.Context, in *SlugInput) (*ListOutput, error) {
	caller, orgID, err := a.resolve(ctx, in.Slug)
	if err != nil {
		return nil, err
	}
	tokens, err := a.service.List(ctx, caller, orgID)
	if err != nil {
		return nil, a.httpError(ctx, err)
	}
	out := &ListOutput{}
	out.Body.Tokens = tokens
	return out, nil
}

func (a *API) issue(ctx context.Context, in *IssueInput) (*IssueOutput, error) {
	return a.issueOrRotate(ctx, in, a.service.Issue)
}

func (a *API) rotate(ctx context.Context, in *IssueInput) (*IssueOutput, error) {
	return a.issueOrRotate(ctx, in, a.service.Rotate)
}

func (a *API) issueOrRotate(ctx context.Context, in *IssueInput, fn func(context.Context, uuid.UUID, uuid.UUID, IssueOptions) (*Issued, error)) (*IssueOutput, error) {
	caller, orgID, err := a.resolve(ctx, in.Slug)
	if err != nil {
		return nil, err
	}
	issued, err := fn(ctx, caller, orgID, IssueOptions{
		Description: in.Body.Description,
		ExpiresIn:   time.Duration(in.Body.ExpiresInSeconds) * time.Second,
	})
	if err != nil {
		return nil, a.httpError(ctx, err)
	}
	return &IssueOutput{Body: issued}, nil
}

func (a *API) revoke(ctx context.Context, in *RevokeInput) (*struct{}, error) {
	caller, orgID, err := a.resolve(ctx, in.Slug)
	if err != nil {
		return nil, err
	}
	id, err := uuid.Parse(in.TokenID)
	if err != nil {
		return nil, huma.Error404NotFound("token not found")
	}
	if err := a.service.Revoke(ctx, caller, orgID, id); err != nil {
		return nil, a.httpError(ctx, err)
	}
	return nil, nil
}

// resolve returns the caller and the organization named by slug.
func (a *API) resolve(ctx context.Context, slug string) (uuid.UUID, uuid.UUID, error) {
	caller, err := a.config.Caller(ctx)
	if errors.Is(err, requestprincipal.ErrNoPrincipal) {
		return uuid.Nil, uuid.Nil, huma.Error401Unauthorized("authentication required")
	}
	if err != nil {
		a.config.Logger.ErrorContext(ctx, "scimtoken: identifying caller", "error", err)
		return uuid.Nil, uuid.Nil, huma.Error500InternalServerError("identifying caller")
	}
	org, _, err := a.config.Organizations.ResolveSlug(ctx, slug)
	if err != nil || org == nil {
		return uuid.Nil, uuid.Nil, huma.Error404NotFound("organization not found")
	}
	return caller, org.ID, nil
}

func (a *API) httpError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrForbidden):
		return huma.Error403Forbidden("not allowed to manage this organization's SCIM tokens")
	case errors.Is(err, ErrNotFound):
		return huma.Error404NotFound("token not found")
	case errors.Is(err, ErrOrganizationNotFound):
		return huma.Error404NotFound("organization not found")
	case errors.Is(err, ErrTokenExists):
		return huma.Error409Conflict(ErrTokenExists.Error())
	case errors.Is(err, ErrConflict):
		return huma.Error409Conflict(ErrConflict.Error())
	default:
		a.config.Logger.ErrorContext(ctx, "scimtoken: request failed", "error", err)
		return huma.Error500InternalServerError("internal error")
	}
}
