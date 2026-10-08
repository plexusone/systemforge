package legacyguard

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goPatterns match references to the retired legacy identity model in Go
// source: the removed Ent packages, table names, and the systemauth names
// replaced by HumanPrincipal.
var goPatterns = []*regexp.Regexp{
	regexp.MustCompile(`systemforge/identity/ent/(user|membership|oauthaccount|refreshtoken|apikey|serviceaccount|serviceaccountkeypair)"`),
	regexp.MustCompile(`\bsf_(users|memberships|oauth_accounts|refresh_tokens|api_keys|service_accounts|service_account_key_pairs)\b`),
	regexp.MustCompile(`\b(LoginPrincipal|ErrUserNotFound|ErrUserExists|GetUserByFederationID|legacyUserID)\b`),
}

// docPatterns match documentation that describes the retired model.
var docPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bsf_(users|memberships|oauth_accounts|refresh_tokens|api_keys|service_accounts|service_account_key_pairs)\b`),
	regexp.MustCompile(`\bclient\.(User|Membership|OAuthAccount|RefreshToken|ServiceAccount)\b`),
}

// historical paths may describe the legacy model as history: the migration
// that removes it, release notes, the changelog, specs and ADRs, and
// design documents.
var historical = []string{
	"migrations/",
	"docs/releases/",
	"docs/specs/",
	"docs/design/",
	"CHANGELOG.md",
	"CHANGELOG.json",
	"internal/legacyguard/",
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found at %s: %v", root, err)
	}
	return root
}

func isHistorical(rel string) bool {
	for _, h := range historical {
		if strings.HasPrefix(rel, h) {
			return true
		}
	}
	return false
}

// TestNoLegacyIdentityReferences fails when Go code or current
// documentation references the retired legacy identity model.
func TestNoLegacyIdentityReferences(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "site", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if isHistorical(rel) {
			return nil
		}
		var patterns []*regexp.Regexp
		switch {
		case strings.HasSuffix(rel, ".go"):
			patterns = goPatterns
		case strings.HasSuffix(rel, ".md"):
			patterns = docPatterns
		default:
			return nil
		}
		return scan(t, path, rel, patterns)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func scan(t *testing.T, path, rel string, patterns []*regexp.Regexp) (err error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		for _, p := range patterns {
			if m := p.FindString(line); m != "" {
				t.Errorf("%s:%d references the retired legacy identity model (%q); see ADR-004", rel, n, m)
			}
		}
	}
	return sc.Err()
}
