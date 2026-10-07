package requestprincipal

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
)

// ErrNoCredentials is returned by an Authenticator when the request carries
// no credentials of its kind, so the next authenticator may try.
var ErrNoCredentials = errors.New("requestprincipal: no credentials")

// Authenticator authenticates requests of one protocol.
//
// Authenticate returns the principal, or:
//
//   - an error wrapping ErrNoCredentials when the request carries none of
//     its credentials;
//   - an *Error when it carries them but they are invalid or insufficient
//     (the response the protocol prescribes: a challenge, 401 or 403);
//   - any other error for an internal failure (a 500).
type Authenticator interface {
	Authenticate(r *http.Request) (*RequestPrincipal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(r *http.Request) (*RequestPrincipal, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(r *http.Request) (*RequestPrincipal, error) { return f(r) }

// Challenger is implemented by authenticators that advertise themselves on
// a 401 response to a request that no authenticator recognized: a bearer
// authenticator adds WWW-Authenticate, an AAuth authenticator adds
// AAuth-Requirement. Challenge adds its headers to h.
type Challenger interface {
	Challenge(h http.Header)
}

// Error is an authentication failure with the response its protocol
// prescribes.
type Error struct {
	// Status is the HTTP status (401 when zero).
	Status int
	// Header holds response headers, such as a challenge.
	Header http.Header
	// Code and Message form the default JSON body
	// {"code": ..., "message": ...}.
	Code    string
	Message string
	// Respond, when set, writes the whole response instead (after Header
	// is applied), for protocols with their own error bodies.
	Respond func(w http.ResponseWriter)
	// Err is the underlying cause, for logs.
	Err error
}

func (e *Error) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Code
	}
	if e.Err != nil {
		if msg == "" {
			return "requestprincipal: " + e.Err.Error()
		}
		return "requestprincipal: " + msg + ": " + e.Err.Error()
	}
	return "requestprincipal: " + msg
}

func (e *Error) Unwrap() error { return e.Err }

// Write writes the response for e.
func (e *Error) Write(w http.ResponseWriter) {
	for k, vs := range e.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if e.Respond != nil {
		e.Respond(w)
		return
	}
	status := e.Status
	if status == 0 {
		status = http.StatusUnauthorized
	}
	code := e.Code
	if code == "" {
		code = "UNAUTHENTICATED"
	}
	writeJSONError(w, status, code, e.Message)
}

type errorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// The status is already sent; an encoding failure here can only be a
	// broken connection, which the client observes directly.
	if err := json.NewEncoder(w).Encode(errorBody{Code: code, Message: message}); err != nil {
		return
	}
}

// Chain tries authenticators in order. It is itself an Authenticator.
type Chain []Authenticator

// Authenticate returns the principal from the first authenticator that
// recognizes the request's credentials. An authenticator that recognizes
// them but rejects them ends the chain with its error: credentials of one
// protocol never fall through to another. When none recognizes the
// request, the result is a 401 *Error carrying every Challenger's headers,
// and wraps ErrNoCredentials.
func (c Chain) Authenticate(r *http.Request) (*RequestPrincipal, error) {
	for _, a := range c {
		p, err := a.Authenticate(r)
		switch {
		case err == nil && p != nil:
			return p, nil
		case err == nil:
			return nil, errors.New("requestprincipal: authenticator returned no principal and no error")
		case errors.Is(err, ErrNoCredentials):
			continue
		default:
			return nil, err
		}
	}
	h := http.Header{}
	c.Challenge(h)
	return nil, &Error{
		Status:  http.StatusUnauthorized,
		Header:  h,
		Code:    "UNAUTHENTICATED",
		Message: "authentication required",
		Err:     ErrNoCredentials,
	}
}

// Challenge implements Challenger with every member's challenges.
func (c Chain) Challenge(h http.Header) {
	for _, a := range c {
		if ch, ok := a.(Challenger); ok {
			ch.Challenge(h)
		}
	}
}

// Options configures Middleware.
type Options struct {
	// Optional lets requests without credentials through without a
	// principal (handlers check FromContext). Invalid credentials are
	// still rejected.
	Optional bool
	// Logger receives internal errors. Default: slog.Default().
	Logger *slog.Logger
}

// Middleware authenticates each request with the authenticators in order
// (see Chain.Authenticate), puts the RequestPrincipal in the request
// context, and otherwise writes the protocol's response: the rejecting
// authenticator's *Error, a 401 with every authenticator's challenge when
// none recognized the request, or a 500 for an internal error.
func Middleware(opts Options, authenticators ...Authenticator) func(http.Handler) http.Handler {
	if len(authenticators) == 0 {
		panic("requestprincipal: Middleware requires at least one authenticator")
	}
	chain := Chain(authenticators)
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := chain.Authenticate(r)
			if err == nil {
				next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
				return
			}
			if opts.Optional && errors.Is(err, ErrNoCredentials) {
				next.ServeHTTP(w, r)
				return
			}
			var authErr *Error
			if errors.As(err, &authErr) {
				authErr.Write(w)
				return
			}
			logger.ErrorContext(r.Context(), "authenticating request", "error", err)
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
		})
	}
}
