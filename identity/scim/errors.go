package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// SCIM error types as defined in RFC 7644 Section 3.12.
const (
	// ErrorTypeInvalidFilter indicates the filter syntax is invalid.
	ErrorTypeInvalidFilter = "invalidFilter"

	// ErrorTypeTooMany indicates too many results would be returned.
	ErrorTypeTooMany = "tooMany"

	// ErrorTypeUniqueness indicates a uniqueness constraint was violated.
	ErrorTypeUniqueness = "uniqueness"

	// ErrorTypeMutability indicates an attempt to modify an immutable attribute.
	ErrorTypeMutability = "mutability"

	// ErrorTypeInvalidSyntax indicates the request body is invalid.
	ErrorTypeInvalidSyntax = "invalidSyntax"

	// ErrorTypeInvalidPath indicates an invalid attribute path.
	ErrorTypeInvalidPath = "invalidPath"

	// ErrorTypeNoTarget indicates no target resource was found for a PATCH operation.
	ErrorTypeNoTarget = "noTarget"

	// ErrorTypeInvalidValue indicates an invalid attribute value.
	ErrorTypeInvalidValue = "invalidValue"

	// ErrorTypeInvalidVers indicates an invalid version for optimistic locking.
	ErrorTypeInvalidVers = "invalidVers"

	// ErrorTypeSensitive indicates a sensitive attribute cannot be returned.
	ErrorTypeSensitive = "sensitive"
)

// Error represents a SCIM error response as defined in RFC 7644 Section 3.12.
type Error struct {
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   int      `json:"status"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.ScimType != "" {
		return fmt.Sprintf("scim: %s (status %d): %s", e.ScimType, e.Status, e.Detail)
	}
	return fmt.Sprintf("scim: status %d: %s", e.Status, e.Detail)
}

// NewError creates a new SCIM error.
func NewError(status int, scimType, detail string) *Error {
	return &Error{
		Schemas:  []string{SchemaError},
		Status:   status,
		ScimType: scimType,
		Detail:   detail,
	}
}

// Common error constructors.

// ErrNotFound creates a 404 Not Found error.
func ErrNotFound(detail string) *Error {
	return NewError(http.StatusNotFound, "", detail)
}

// ErrConflict creates a 409 Conflict error for uniqueness violations.
func ErrConflict(detail string) *Error {
	return NewError(http.StatusConflict, ErrorTypeUniqueness, detail)
}

// ErrBadRequest creates a 400 Bad Request error.
func ErrBadRequest(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeInvalidSyntax, detail)
}

// ErrInvalidFilter creates a 400 Bad Request error for invalid filters.
func ErrInvalidFilter(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeInvalidFilter, detail)
}

// ErrInvalidPath creates a 400 Bad Request error for invalid attribute paths.
func ErrInvalidPath(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeInvalidPath, detail)
}

// ErrInvalidValue creates a 400 Bad Request error for invalid values.
func ErrInvalidValue(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeInvalidValue, detail)
}

// ErrInvalidSyntax creates a 400 Bad Request error for invalid request syntax.
func ErrInvalidSyntax(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeInvalidSyntax, detail)
}

// ErrMutability creates a 400 Bad Request error for immutable attribute modifications.
func ErrMutability(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeMutability, detail)
}

// ErrNoTarget creates a 400 Bad Request error when PATCH target is not found.
func ErrNoTarget(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeNoTarget, detail)
}

// ErrUnauthorized creates a 401 Unauthorized error.
func ErrUnauthorized(detail string) *Error {
	return NewError(http.StatusUnauthorized, "", detail)
}

// ErrForbidden creates a 403 Forbidden error.
func ErrForbidden(detail string) *Error {
	return NewError(http.StatusForbidden, "", detail)
}

// ErrPreconditionFailed creates a 412 Precondition Failed error for ETag mismatches.
func ErrPreconditionFailed(detail string) *Error {
	return NewError(http.StatusPreconditionFailed, ErrorTypeInvalidVers, detail)
}

// ErrTooMany creates a 400 Bad Request error when too many resources would be returned.
func ErrTooMany(detail string) *Error {
	return NewError(http.StatusBadRequest, ErrorTypeTooMany, detail)
}

// ErrInternal creates a 500 Internal Server Error.
func ErrInternal(detail string) *Error {
	return NewError(http.StatusInternalServerError, "", detail)
}

// ErrNotImplemented creates a 501 Not Implemented error.
func ErrNotImplemented(detail string) *Error {
	return NewError(http.StatusNotImplemented, "", detail)
}

// WriteError writes a SCIM error response to the HTTP response writer.
func WriteError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(err.Status)
	_ = json.NewEncoder(w).Encode(err)
}

// internalErrorDetail is the detail of every 500 error built from an
// unexpected error: the underlying text, which may carry SQL, driver or
// schema details, is logged, never sent to the client.
const internalErrorDetail = "internal error"

// InternalError logs err with the request's logger (LoggerFromContext) and
// returns a 500 SCIM error whose detail does not carry err's text. Stores
// should use it for database and other unexpected errors.
func InternalError(ctx context.Context, err error) *Error {
	LoggerFromContext(ctx).Error("scim: internal error", "error", err)
	return ErrInternal(internalErrorDetail)
}

// ToSCIMError converts a standard error to a SCIM error.
// If the error is, or wraps, a SCIM error, that error is returned.
// Otherwise, a 500 Internal Server Error without the error's text is
// returned; use toSCIMError where a request context is available, so the
// error is also logged.
func ToSCIMError(err error) *Error {
	var scimErr *Error
	if errors.As(err, &scimErr) {
		return scimErr
	}
	return ErrInternal(internalErrorDetail)
}

// toSCIMError is ToSCIMError that logs an error it does not pass through.
func toSCIMError(ctx context.Context, err error) *Error {
	var scimErr *Error
	if errors.As(err, &scimErr) {
		return scimErr
	}
	return InternalError(ctx, err)
}
