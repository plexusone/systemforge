package relyingparty

import (
	"net/http"
	"testing"
)

// newTestClient returns a Client for md that talks to SystemAuth with
// httpClient.
func newTestClient(t *testing.T, issuer string, httpClient *http.Client, md Metadata) *Client {
	t.Helper()
	if issuer == "" {
		issuer = "https://auth.example.com"
	}
	c, err := NewClientWithMetadata(Config{
		Issuer: issuer, ClientID: "app", RedirectURL: "https://app.example.com/callback", HTTPClient: httpClient,
	}, md)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
