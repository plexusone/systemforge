package systemauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/plexusone/systemforge/contract/audit"
	"github.com/plexusone/systemforge/session/clientaddr"
)

// Behind a trusted reverse proxy, security events record the visitor's
// address from the proxy's header, not the proxy's own address.
func TestSecurityEventsUseTheClientAddressRule(t *testing.T) {
	events := &eventCapture{}
	s := newRefreshTestServer(t, WithAuditEmitter(events), WithClientAddressResolver(clientaddr.MustNew(clientaddr.LoopbackProxy())))

	form := url.Values{"grant_type": {"authorization_code"}, "code": {"not-a-code"}, "client_id": {"spa"}, "redirect_uri": {testRPCB}, "code_verifier": {testVerifier}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:41000"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	withTokenProof(t, req)
	s.ServeHTTP(httptest.NewRecorder(), req)

	refused := events.find(EventTokenRefused, audit.OutcomeFailure)
	if len(refused) == 0 {
		t.Fatal("no token refusal event")
	}
	if got := refused[0].Context.ClientIP; got != "203.0.113.7" {
		t.Errorf("event client_ip = %q, want the forwarded visitor 203.0.113.7", got)
	}
}
