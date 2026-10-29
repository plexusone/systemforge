package legacyguard

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// rule is one forbidden pattern. A match listed in allow is not reported.
type rule struct {
	re     *regexp.Regexp
	reason string
	allow  map[string]bool
}

const (
	legacyModel = "references the retired legacy identity model; see ADR-004"
	coreEra     = "uses a retired Core-era name; see ADR-001"
	upstream    = "wires an upstream GitHub/Google OAuth endpoint outside identity/oauthclient"
)

// coreEraNames match the Core-era service and link-field names that ADR-001
// retired, in any case (COREAUTH_* environment variables included).
var coreEraNames = &rule{
	re:     regexp.MustCompile(`(?i)\b(coreauth|corecontrol|core_control|core_auth)`),
	reason: coreEra,
}

// cfPrefix matches the Core-era cf_ table, cookie and API-key prefix.
// Cloudflare's own names (the cf_ray, cf_country, ... session metadata
// keys copied from CF-* request headers) are legitimate and allowed.
var cfPrefix = &rule{
	re:     regexp.MustCompile(`\bcf_[A-Za-z0-9_]*`),
	reason: coreEra,
	allow: map[string]bool{
		"cf_ray":           true,
		"cf_country":       true,
		"cf_visitor":       true,
		"cf_bot_score":     true,
		"cf_connecting_ip": true,
		"cf_ipcountry":     true,
	},
}

// upstreamOAuth matches upstream social-login endpoint wiring: the GitHub
// and Google authorization, token and userinfo endpoints and the
// golang.org/x/oauth2 endpoint packages. Only identity/oauthclient wires
// them; everything else goes through it.
var upstreamOAuth = &rule{
	re:     regexp.MustCompile(`github\.com/login/oauth|api\.github\.com/user|accounts\.google\.com/o/oauth2|oauth2\.googleapis\.com|googleapis\.com/oauth2|openidconnect\.googleapis\.com|golang\.org/x/oauth2/(github|google)\b`),
	reason: upstream,
}

// upstreamOAuthHome is the one package allowed to match upstreamOAuth.
const upstreamOAuthHome = "identity/oauthclient/"

// goRules match references to retired names in Go source: the removed
// Ent packages, table names, and the systemauth names replaced by
// HumanPrincipal, and the Core-era names.
var goRules = []*rule{
	{re: regexp.MustCompile(`systemforge/identity/ent/(user|membership|oauthaccount|refreshtoken|apikey|serviceaccount|serviceaccountkeypair)"`), reason: legacyModel},
	{re: regexp.MustCompile(`\bsf_(users|memberships|oauth_accounts|refresh_tokens|api_keys|service_accounts|service_account_key_pairs)\b`), reason: legacyModel},
	{re: regexp.MustCompile(`\b(LoginPrincipal|ErrUserNotFound|ErrUserExists|GetUserByFederationID|legacyUserID)\b`), reason: legacyModel},
	coreEraNames,
	cfPrefix,
}

// docRules match documentation that describes the retired models.
var docRules = []*rule{
	{re: regexp.MustCompile(`\bsf_(users|memberships|oauth_accounts|refresh_tokens|api_keys|service_accounts|service_account_key_pairs)\b`), reason: legacyModel},
	{re: regexp.MustCompile(`\bclient\.(User|Membership|OAuthAccount|RefreshToken|ServiceAccount)\b`), reason: legacyModel},
	coreEraNames,
	cfPrefix,
}

// configRules match retired names in SQL, YAML and JSON files.
var configRules = []*rule{coreEraNames, cfPrefix}

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

// rulesFor returns the rules that apply to the file at rel.
func rulesFor(rel string) []*rule {
	switch {
	case strings.HasSuffix(rel, ".go"):
		if strings.HasPrefix(rel, upstreamOAuthHome) {
			return goRules
		}
		return append(goRules[:len(goRules):len(goRules)], upstreamOAuth)
	case strings.HasSuffix(rel, ".md"):
		return docRules
	case strings.HasSuffix(rel, ".sql"), strings.HasSuffix(rel, ".yaml"),
		strings.HasSuffix(rel, ".yml"), strings.HasSuffix(rel, ".json"):
		return configRules
	default:
		return nil
	}
}

// TestNoLegacyReferences fails when code, configuration or current
// documentation references a retired name: the legacy identity model
// (ADR-004), the Core-era names (ADR-001), or upstream OAuth endpoints
// wired outside identity/oauthclient.
func TestNoLegacyReferences(t *testing.T) {
	root := repoRoot(t)
	// Files are opened through an os.Root so reads cannot leave the repository.
	repo, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := repo.Close(); err != nil {
			t.Errorf("closing repository root: %v", err)
		}
	}()
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
			// .claude holds local agent settings and worktrees, never
			// committed code.
			case ".git", ".claude", "node_modules", "site", "vendor":
				return filepath.SkipDir
			}
			if isNestedCheckout(root, path) {
				return filepath.SkipDir
			}
			return nil
		}
		if isHistorical(rel) {
			return nil
		}
		rules := rulesFor(rel)
		if len(rules) == 0 {
			return nil
		}
		return scan(t, repo, rel, rules)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// findings returns the forbidden matches of rules in line.
func findings(line string, rules []*rule) []finding {
	var out []finding
	for _, r := range rules {
		for _, m := range r.re.FindAllString(line, -1) {
			if !r.allow[m] {
				out = append(out, finding{match: m, reason: r.reason})
			}
		}
	}
	return out
}

type finding struct{ match, reason string }

func scan(t *testing.T, repo *os.Root, rel string, rules []*rule) (err error) {
	t.Helper()
	f, err := repo.Open(filepath.FromSlash(rel))
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
		for _, fd := range findings(sc.Text(), rules) {
			t.Errorf("%s:%d %s (%q)", rel, n, fd.reason, fd.match)
		}
	}
	return sc.Err()
}

// TestRules checks each rule against lines it must and must not flag.
func TestRules(t *testing.T) {
	for _, tc := range []struct {
		file, line string
		flagged    bool
	}{
		{"x.go", `import "github.com/plexusone/systemforge/identity/coreauth"`, true},
		{"x.go", `os.Getenv("COREAUTH_ISSUER")`, true},
		{"x.go", `field.String("core_control_principal_id")`, true},
		{"x.go", `field.String("core_auth_principal_id")`, true},
		{"x.go", `// the corecontrol service`, true},
		{"x.go", `entsql.Annotation{Table: "cf_principals"}`, true},
		{"x.go", `const prefix = "cf_live_"`, true},
		{"x.sql", `ALTER TABLE cf_organizations RENAME TO sf_organizations;`, true},
		{"x.yaml", `cookie: cf_session`, true},
		{"x.md", "Table `cf_oauth_tokens`", true},
		{"x.go", `metadata["cf_ray"] = ray`, false},
		{"x.go", `metadata["cf_bot_score"] = s`, false},
		{"x.go", `r.Header.Get("CF-Connecting-IP")`, false},
		{"x.go", `score_auth := 1; scorecard_x := 2`, false},
		{"x.go", `"github.com/plexusone/systemforge/identity/systemauth"`, false},
		{"x.go", `"golang.org/x/oauth2/github"`, true},
		{"x.go", `"golang.org/x/oauth2/google"`, true},
		{"x.go", `u := "https://github.com/login/oauth/authorize"`, true},
		{"x.go", `u := "https://oauth2.googleapis.com/token"`, true},
		{"x.go", `u := "https://accounts.google.com/o/oauth2/v2/auth"`, true},
		{"x.go", `u := "https://www.googleapis.com/oauth2/v3/userinfo"`, true},
		{"x.go", `"golang.org/x/oauth2"`, false},
		{"identity/oauthclient/client.go", `"golang.org/x/oauth2/github"`, false},
		{"identity/oauthclient/connector.go", `u := "https://www.googleapis.com/oauth2/v3/userinfo"`, false},
		{"x.md", `see https://github.com/login/oauth/authorize`, false},
	} {
		got := len(findings(tc.line, rulesFor(tc.file))) > 0
		if got != tc.flagged {
			t.Errorf("%s: %q flagged = %v, want %v", tc.file, tc.line, got, tc.flagged)
		}
	}
}

// isNestedCheckout reports whether dir, below the module root, is another
// git checkout: a worktree or a nested repository, which carries its own
// .git file or directory and its own copy of the code.
func isNestedCheckout(root, dir string) bool {
	if dir == root {
		return false
	}
	_, err := os.Lstat(filepath.Join(dir, ".git"))
	return err == nil
}
