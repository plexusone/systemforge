package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"github.com/google/uuid"
	"github.com/plexusone/systemforge/session/middleware"
)

// Middleware wraps an Authorizer for HTTP middleware use.
type Middleware struct {
	authorizer Authorizer
}

// NewMiddleware creates a new authorization middleware.
func NewMiddleware(authorizer Authorizer) *Middleware {
	return &Middleware{authorizer: authorizer}
}

// RequireAction returns middleware that checks if the user can perform
// an action on a resource type.
func (m *Middleware) RequireAction(resourceType ResourceType, action Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			resource := NewResource(resourceType)
			if claims.OrganizationID != nil {
				resource = resource.WithOrg(*claims.OrganizationID)
			}

			allowed, err := m.authorizer.Can(r.Context(), principal, action, resource)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "authorization check failed")
				return
			}

			if !allowed {
				writeForbidden(w, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyAction returns middleware that checks if the user can perform
// any of the specified actions on a resource type. It panics when no
// action is given.
func (m *Middleware) RequireAnyAction(resourceType ResourceType, actions ...Action) func(http.Handler) http.Handler {
	return m.requireActions(resourceType, actions, false)
}

// RequireAllActions returns middleware that checks if the user can perform
// all of the specified actions on a resource type. It panics when no
// action is given, because a route that requires all of no actions would
// otherwise be open to every authenticated caller.
func (m *Middleware) RequireAllActions(resourceType ResourceType, actions ...Action) func(http.Handler) http.Handler {
	return m.requireActions(resourceType, actions, true)
}

// requireActions is a helper that creates middleware for checking multiple actions.
// If requireAll is true, all actions must be allowed; otherwise any single action suffices.
func (m *Middleware) requireActions(resourceType ResourceType, actions []Action, requireAll bool) func(http.Handler) http.Handler {
	if len(actions) == 0 {
		panic(fmt.Sprintf("authz: no actions given for resource type %q", resourceType))
	}
	actions = slices.Clone(actions)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			resource := NewResource(resourceType)
			if claims.OrganizationID != nil {
				resource = resource.WithOrg(*claims.OrganizationID)
			}

			var allowed bool
			var err error
			if requireAll {
				allowed, err = m.authorizer.CanAll(r.Context(), principal, actions, resource)
			} else {
				allowed, err = m.authorizer.CanAny(r.Context(), principal, actions, resource)
			}
			if err != nil {
				writeError(w, http.StatusInternalServerError, "authorization check failed")
				return
			}

			if !allowed {
				writeForbidden(w, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OrgMiddleware wraps an OrgAuthorizer for organization-scoped middleware.
type OrgMiddleware struct {
	authorizer OrgAuthorizer
}

// NewOrgMiddleware creates a new organization-scoped authorization middleware.
func NewOrgMiddleware(authorizer OrgAuthorizer) *OrgMiddleware {
	return &OrgMiddleware{authorizer: authorizer}
}

// RequireMembership returns middleware that requires the user to be a member
// of the current organization.
func (m *OrgMiddleware) RequireMembership() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			if claims.OrganizationID == nil {
				writeForbidden(w, "no organization context")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			isMember, err := m.authorizer.IsMember(r.Context(), principal, *claims.OrganizationID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "membership check failed")
				return
			}

			if !isMember {
				writeForbidden(w, "not a member of this organization")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole returns middleware that requires a specific role in the
// current organization.
func (m *OrgMiddleware) RequireRole(role string, hierarchy RoleHierarchy) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			if claims.OrganizationID == nil {
				writeForbidden(w, "no organization context")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			userRole, err := m.authorizer.GetRole(r.Context(), principal, *claims.OrganizationID)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "role check failed")
				return
			}

			if userRole == "" {
				writeForbidden(w, "not a member of this organization")
				return
			}

			if userRole != role && !hierarchy.CanAccess(userRole, role) {
				writeForbidden(w, "insufficient role")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// PlatformMiddleware wraps a PlatformAuthorizer for platform-level middleware.
type PlatformMiddleware struct {
	authorizer PlatformAuthorizer
}

// NewPlatformMiddleware creates a new platform-level authorization middleware.
func NewPlatformMiddleware(authorizer PlatformAuthorizer) *PlatformMiddleware {
	return &PlatformMiddleware{authorizer: authorizer}
}

// RequirePlatformAdmin returns middleware that requires platform admin status.
func (m *PlatformMiddleware) RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			isAdmin, err := m.authorizer.IsPlatformAdmin(r.Context(), principal)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "admin check failed")
				return
			}

			if !isAdmin {
				writeForbidden(w, "platform admin required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ResourceExtractor is a function that extracts a resource from an HTTP request.
// Use this for routes that include resource IDs in the path. The extractor
// must set the resource's owning organization (Resource.OrgID) when
// authorization depends on it; see WithResourceLookup.
type ResourceExtractor func(r *http.Request) (Resource, error)

// RequireResourceAction returns middleware that extracts a resource from
// the request and checks if the user can perform an action on it.
//
// The resource's organization comes only from the extractor, never from
// the caller's token: a resource of another organization must not be
// checked against the caller's role in their own. Use WithResourceLookup
// so the check runs against the organization that owns the resource. A
// resource without an organization is checked by owner and resource
// grants only (rbac), or by its ID (SpiceDB).
//
// Extractor errors answer 400 for a missing or malformed ID, 403 for
// ErrResourceNotFound (so a caller cannot tell another organization's
// resource from a missing one), and 500 otherwise.
func (m *Middleware) RequireResourceAction(extractor ResourceExtractor, action Action) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := middleware.ClaimsFromContext(r.Context())
			if claims == nil {
				writeForbidden(w, "no claims in context")
				return
			}

			resource, err := extractor(r)
			switch {
			case err == nil:
			case errors.Is(err, ErrMissingResourceID), errors.Is(err, ErrInvalidResourceID):
				writeError(w, http.StatusBadRequest, "invalid resource")
				return
			case errors.Is(err, ErrResourceNotFound):
				writeForbidden(w, "insufficient permissions")
				return
			default:
				writeError(w, http.StatusInternalServerError, "resource lookup failed")
				return
			}

			principal := NewUserPrincipal(claims.PrincipalID)
			allowed, err := m.authorizer.Can(r.Context(), principal, action, resource)
			if err != nil {
				writeError(w, http.StatusInternalServerError, "authorization check failed")
				return
			}

			if !allowed {
				writeForbidden(w, "insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// WithResourceID creates a ResourceExtractor that parses a resource ID from
// a URL path parameter. The resource has no organization; use
// WithResourceLookup when authorization depends on the owning organization.
func WithResourceID(resourceType ResourceType, pathParamName string, getParam func(r *http.Request, key string) string) ResourceExtractor {
	return func(r *http.Request) (Resource, error) {
		idStr := getParam(r, pathParamName)
		if idStr == "" {
			return Resource{}, ErrMissingResourceID
		}
		id, err := uuid.Parse(idStr)
		if err != nil {
			return Resource{}, ErrInvalidResourceID
		}
		return NewResourceWithID(resourceType, id), nil
	}
}

// ResourceOrgLookup returns the organization that owns a resource. It
// returns ErrResourceNotFound when the resource does not exist.
type ResourceOrgLookup func(ctx context.Context, id uuid.UUID) (orgID uuid.UUID, err error)

// WithResourceLookup is WithResourceID that also loads the resource's
// owning organization from storage, so RequireResourceAction checks the
// caller's role in that organization.
func WithResourceLookup(resourceType ResourceType, pathParamName string, getParam func(r *http.Request, key string) string, lookup ResourceOrgLookup) ResourceExtractor {
	byID := WithResourceID(resourceType, pathParamName, getParam)
	return func(r *http.Request) (Resource, error) {
		resource, err := byID(r)
		if err != nil {
			return Resource{}, err
		}
		orgID, err := lookup(r.Context(), *resource.ID)
		if err != nil {
			return Resource{}, err
		}
		return resource.WithOrg(orgID), nil
	}
}

// Error types for resource extraction.
var (
	ErrMissingResourceID = &middlewareError{msg: "missing resource ID"}
	ErrInvalidResourceID = &middlewareError{msg: "invalid resource ID"}
	// ErrResourceNotFound is returned by a ResourceOrgLookup for a resource
	// that does not exist.
	ErrResourceNotFound = &middlewareError{msg: "resource not found"}
)

type middlewareError struct {
	msg string
}

func (e *middlewareError) Error() string {
	return e.msg
}

// ErrorResponse represents an error response body.
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

func writeForbidden(w http.ResponseWriter, message string) {
	writeError(w, http.StatusForbidden, message)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(status),
		Message: message,
	}); err != nil {
		// The status is already sent; the client sees a truncated body.
		slog.Error("authz: writing error response", "status", status, "error", err)
	}
}
