package systemauth

import (
	"errors"
	"net/http"

	"github.com/ory/fosite"
)

// MaxTokenRequestBody is the largest token request body accepted, ample
// for any grant.
const MaxTokenRequestBody = 1 << 20

// ParseTokenRequest limits the body of a token endpoint request to
// MaxTokenRequestBody and parses its form. Call it before anything reads
// the request (FormValue, PostFormValue or Fosite), so a large body cannot
// exhaust memory. The error is an RFC 6749 error to write with
// WriteAccessError.
func ParseTokenRequest(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxTokenRequestBody)
	if err := r.ParseForm(); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return fosite.ErrInvalidRequest.WithHint("The request body is too large.").WithWrap(err)
		}
		return fosite.ErrInvalidRequest.WithHint("The request body could not be parsed.").WithWrap(err)
	}
	return nil
}
