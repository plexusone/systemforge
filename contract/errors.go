package contract

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/plexusone/systemforge/internal/apierror"
)

// Error codes as defined in the product contract specification.
const (
	ErrorCodeNotFederated     = "NOT_FEDERATED"
	ErrorCodeSyncInProgress   = "SYNC_IN_PROGRESS"
	ErrorCodeIdentityConflict = "IDENTITY_CONFLICT"
	ErrorCodePolicyInvalid    = "POLICY_INVALID"
	ErrorCodeUnauthorized     = "UNAUTHORIZED"
	ErrorCodeForbidden        = "FORBIDDEN"
	ErrorCodeNotFound         = "NOT_FOUND"
	ErrorCodeBadRequest       = "BAD_REQUEST"
	ErrorCodeInternal         = "INTERNAL_ERROR"
)

// Error represents a contract error response.
type Error struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
	status  int
}

// ErrorResponse wraps an Error for JSON serialization.
type ErrorResponse struct {
	Error *Error `json:"error"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("contract: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("contract: %s", e.Message)
}

// Status returns the HTTP status code for this error.
func (e *Error) Status() int {
	return e.status
}

// NewError creates a new contract error.
func NewError(status int, code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
		status:  status,
	}
}

// NewErrorWithDetails creates a new contract error with additional details.
func NewErrorWithDetails(status int, code, message string, details map[string]any) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Details: details,
		status:  status,
	}
}

// ErrNotFound creates a 404 Not Found error.
func ErrNotFound(message string) *Error {
	return NewError(http.StatusNotFound, ErrorCodeNotFound, message)
}

// ErrBadRequest creates a 400 Bad Request error.
func ErrBadRequest(message string) *Error {
	return NewError(http.StatusBadRequest, ErrorCodeBadRequest, message)
}

// ErrUnauthorized creates a 401 Unauthorized error.
func ErrUnauthorized(message string) *Error {
	return NewError(http.StatusUnauthorized, ErrorCodeUnauthorized, message)
}

// ErrForbidden creates a 403 Forbidden error.
func ErrForbidden(message string) *Error {
	return NewError(http.StatusForbidden, ErrorCodeForbidden, message)
}

// ErrNotFederated creates a 503 error for operations requiring federation.
func ErrNotFederated(message string) *Error {
	return NewError(http.StatusServiceUnavailable, ErrorCodeNotFederated, message)
}

// ErrSyncInProgress creates a 409 Conflict error when sync is already running.
func ErrSyncInProgress(message string) *Error {
	return NewError(http.StatusConflict, ErrorCodeSyncInProgress, message)
}

// ErrIdentityConflict creates a 409 Conflict error for identity mapping conflicts.
func ErrIdentityConflict(identifier string, existingID string) *Error {
	return NewErrorWithDetails(
		http.StatusConflict,
		ErrorCodeIdentityConflict,
		"Principal with identifier already exists",
		map[string]any{
			"identifier":  identifier,
			"existing_id": existingID,
		},
	)
}

// ErrPolicyInvalid creates a 400 Bad Request error for invalid policies.
func ErrPolicyInvalid(message string) *Error {
	return NewError(http.StatusBadRequest, ErrorCodePolicyInvalid, message)
}

// ErrInternal creates a 500 Internal Server Error.
func ErrInternal(message string) *Error {
	return NewError(http.StatusInternalServerError, ErrorCodeInternal, message)
}

// WriteError writes a contract error response to the HTTP response writer.
func WriteError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Status())
	_ = json.NewEncoder(w).Encode(ErrorResponse{Error: err})
}

// ToContractError converts a standard error to a contract error.
// If the error is, or wraps, a contract error, that error is returned.
// Otherwise, a 500 Internal Server Error is returned whose message does not
// carry the error's text, which may hold database or provider details;
// log the error before converting it.
func ToContractError(err error) *Error {
	var contractErr *Error
	if errors.As(err, &contractErr) {
		return contractErr
	}
	return ErrInternal(apierror.InternalMessage)
}
