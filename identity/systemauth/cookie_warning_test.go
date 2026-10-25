package systemauth

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/plexusone/systemforge/identity/oauthclient"
)

// lockedBuffer is a log sink safe for concurrent writes.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestInsecureCookiesWarnAtStartup expects one warning when social login
// starts with InsecureCookies, and none without it.
func TestInsecureCookiesWarnAtStartup(t *testing.T) {
	for _, insecure := range []bool{false, true} {
		var logs lockedBuffer
		connector := oauthclient.NewGitHubConnector(oauthclient.ProviderConfig{
			ClientID: "gh-client", ClientSecret: "gh-secret", RedirectURL: testIssuer + "/login/github/callback",
		})
		_, err := NewEmbedded(Config{
			Issuer: testIssuer,
			SocialLogin: &SocialLoginConfig{
				InsecureCookies: insecure,
			},
		}, WithSocialConnector(connector), WithLogger(slog.New(slog.NewTextHandler(&logs, nil))))
		if err != nil {
			t.Fatalf("NewEmbedded: %v", err)
		}
		want := 0
		if insecure {
			want = 1
		}
		if got := strings.Count(logs.String(), "InsecureCookies is set"); got != want {
			t.Errorf("InsecureCookies=%v: %d warnings, want %d:\n%s", insecure, got, want, logs.String())
		}
	}
}
