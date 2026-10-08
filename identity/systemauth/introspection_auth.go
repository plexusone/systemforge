package systemauth

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// IntrospectionScope is the scope an access token must carry to be used
// as the credential for calling the introspection endpoint.
const IntrospectionScope = "introspect"

// AuthorizeIntrospectionCaller reports whether the caller of a token
// introspection request (RFC 7662 section 2.1) may introspect tokens.
// Fosite accepts any valid access token, or any client's Basic
// credentials, public clients included, so a token or a public client_id
// obtained anywhere would let its holder test other parties' tokens and
// read their subject, scopes, client, and audience. A caller must be:
//
//   - a confidential client, authenticating with HTTP Basic or a client
//     assertion (Fosite verifies the secret or signature afterwards), or
//   - the bearer of an access token carrying IntrospectionScope.
//
// clientPublic reports whether a client ID is registered and public.
// bearerScopes returns the scopes of an active access token, or nil.
func AuthorizeIntrospectionCaller(r *http.Request, clientPublic func(clientID string) (known, public bool), bearerScopes func(token string) []string) bool {
	if user, _, ok := r.BasicAuth(); ok {
		id, err := url.QueryUnescape(user)
		if err != nil || id == "" {
			return false
		}
		known, public := clientPublic(id)
		return known && !public
	}
	if auth := r.Header.Get("Authorization"); auth != "" {
		scheme, token, ok := strings.Cut(auth, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return false
		}
		for _, sc := range bearerScopes(strings.TrimSpace(token)) {
			if sc == IntrospectionScope {
				return true
			}
		}
		return false
	}
	// Private-key JWT client authentication: only confidential clients can
	// use it, and Fosite verifies the assertion.
	return r.PostFormValue("client_assertion") != ""
}

// writeIntrospectionUnauthorized answers an unauthorized introspection
// caller per RFC 7662 / RFC 6749.
func writeIntrospectionUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="introspection", Bearer`)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusUnauthorized)
	if _, err := w.Write([]byte(`{"error":"invalid_client"}`)); err != nil {
		// The status is already sent; the client sees a truncated body.
		slog.Error("writing introspection error", "error", err)
	}
}
