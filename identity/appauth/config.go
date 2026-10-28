package appauth

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/grokify/goauth/dpop"
)

// DefaultBasePath is where the browser sign-in surface (/bff/*) is mounted
// when Config.BasePath is empty.
const DefaultBasePath = "/bff"

// Config is an application's sign-in configuration: who SystemAuth is, how
// the application is registered there, and where it is reached.
//
//nolint:gosec // G117: ClientSecret is the OAuth field name; the value comes from the environment
type Config struct {
	// Issuer is SystemAuth's issuer URL.
	Issuer string
	// ClientID is the application's OAuth client at SystemAuth.
	ClientID string
	// ClientSecret is the confidential client's secret. Empty for a public
	// client.
	ClientSecret string
	// PublicURL is the origin the application is reached at, such as
	// https://app.example.com. The redirect URL and the DPoP proof URL are
	// built from it.
	PublicURL string
	// AllowedOrigins are other origins that may call the BFF and be
	// post-login return targets.
	AllowedOrigins []string
	// AccessTokenAudience, when set, must be in the aud of access tokens
	// the application's API accepts.
	AccessTokenAudience string
	// AcceptedClientIDs are other OAuth clients whose access tokens the API
	// accepts, such as a command-line tool's. ClientID is always accepted.
	AcceptedClientIDs []string
	// Scopes are requested at sign-in in addition to
	// relyingparty.DefaultScopes.
	Scopes []string
	// DPoPKey is the PEM P-256 private key the application proves
	// possession of to SystemAuth. Sessions' tokens are bound to it, so it
	// must survive restarts and be shared by every instance.
	DPoPKey string
	// DPoPKeyFile is a file holding DPoPKey, for deployments that deliver
	// secrets as files. Set one of DPoPKey and DPoPKeyFile.
	DPoPKeyFile string
	// BasePath is where the BFF is mounted. Default: DefaultBasePath.
	BasePath string
}

// Labels name the settings in Validate's errors, so a host can point at its
// own variable or file keys. ConfigFromEnv returns labels of the form
// "Issuer (APP_SYSTEMAUTH_ISSUER)"; a host may replace the parenthesized part.
type Labels struct {
	Issuer, ClientID, PublicURL, AllowedOrigins, AccessTokenAudience,
	AcceptedClientIDs, DPoPKey, DPoPKeyFile string
}

// DefaultLabels are plain setting names.
var DefaultLabels = Labels{
	Issuer:              "issuer",
	ClientID:            "client ID",
	PublicURL:           "public URL",
	AllowedOrigins:      "allowed origin",
	AccessTokenAudience: "access token audience",
	AcceptedClientIDs:   "accepted client ID",
	DPoPKey:             "DPoP key",
	DPoPKeyFile:         "DPoP key file",
}

// Environment variable suffixes read by ConfigFromEnv, after the prefix and
// an underscore.
const (
	EnvIssuer              = "SYSTEMAUTH_ISSUER"
	EnvClientID            = "CLIENT_ID"
	EnvClientSecret        = "CLIENT_SECRET" //nolint:gosec // G101: an environment variable name, not a credential
	EnvPublicURL           = "PUBLIC_URL"
	EnvAllowedOrigins      = "ALLOWED_ORIGINS"
	EnvAccessTokenAudience = "ACCESS_TOKEN_AUDIENCE"
	EnvAcceptedClientIDs   = "ACCEPTED_CLIENT_IDS"
	EnvDPoPKey             = "DPOP_KEY"
	EnvDPoPKeyFile         = "DPOP_KEY_FILE"
)

// ConfigFromEnv reads the configuration from environment variables named
// prefix + "_" + one of the Env* suffixes, and returns labels naming them.
// List values are comma-separated.
func ConfigFromEnv(prefix string) (Config, Labels) {
	name := func(suffix string) string { return prefix + "_" + suffix }
	label := func(field, suffix string) string { return field + " (" + name(suffix) + ")" }
	cfg := Config{
		Issuer:              os.Getenv(name(EnvIssuer)),
		ClientID:            os.Getenv(name(EnvClientID)),
		ClientSecret:        os.Getenv(name(EnvClientSecret)),
		PublicURL:           os.Getenv(name(EnvPublicURL)),
		AllowedOrigins:      splitList(os.Getenv(name(EnvAllowedOrigins))),
		AccessTokenAudience: os.Getenv(name(EnvAccessTokenAudience)),
		AcceptedClientIDs:   splitList(os.Getenv(name(EnvAcceptedClientIDs))),
		DPoPKey:             os.Getenv(name(EnvDPoPKey)),
		DPoPKeyFile:         os.Getenv(name(EnvDPoPKeyFile)),
	}
	labels := Labels{
		Issuer:              label("Issuer", EnvIssuer),
		ClientID:            label("ClientID", EnvClientID),
		PublicURL:           label("PublicURL", EnvPublicURL),
		AllowedOrigins:      label("AllowedOrigins", EnvAllowedOrigins),
		AccessTokenAudience: label("AccessTokenAudience", EnvAccessTokenAudience),
		AcceptedClientIDs:   label("AcceptedClientIDs", EnvAcceptedClientIDs),
		DPoPKey:             label("DPoPKey", EnvDPoPKey),
		DPoPKeyFile:         label("DPoPKeyFile", EnvDPoPKeyFile),
	}
	return cfg, labels
}

func splitList(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// Configured reports whether any sign-in setting is present, so a host can
// tell "not configured" from "configured wrongly".
func (c Config) Configured() bool {
	return c.Issuer != "" || c.ClientID != "" || c.ClientSecret != "" || c.PublicURL != "" ||
		len(c.AllowedOrigins) > 0 || c.AccessTokenAudience != "" || len(c.AcceptedClientIDs) > 0 ||
		c.DPoPKey != "" || c.DPoPKeyFile != ""
}

// Validate checks the configuration and reports every problem, each
// starting with its label. The DPoP key is required.
func (c Config) Validate(l Labels) error { return c.validate(l, true) }

func (c Config) validate(l Labels, keyRequired bool) error {
	var errs []error
	if c.Issuer == "" {
		errs = append(errs, fmt.Errorf("%s is required", l.Issuer))
	} else if _, err := parseURL(l.Issuer, c.Issuer); err != nil {
		errs = append(errs, err)
	}
	if c.ClientID == "" {
		errs = append(errs, fmt.Errorf("%s is required", l.ClientID))
	}
	if c.PublicURL == "" {
		errs = append(errs, fmt.Errorf("%s is required", l.PublicURL))
	} else if err := checkOrigin(l.PublicURL, c.PublicURL); err != nil {
		errs = append(errs, err)
	}
	for _, o := range c.AllowedOrigins {
		if err := checkOrigin(l.AllowedOrigins, o); err != nil {
			errs = append(errs, err)
		}
	}
	for _, id := range c.AcceptedClientIDs {
		if strings.TrimSpace(id) == "" {
			errs = append(errs, fmt.Errorf("%s must not be empty", l.AcceptedClientIDs))
		}
	}
	errs = append(errs, c.validateKey(l, keyRequired)...)
	return errors.Join(errs...)
}

func (c Config) validateKey(l Labels, required bool) []error {
	switch {
	case c.DPoPKey != "" && c.DPoPKeyFile != "":
		return []error{fmt.Errorf("%s and %s are both set", l.DPoPKey, l.DPoPKeyFile)}
	case c.DPoPKey != "":
		if _, err := ParseDPoPKey(c.DPoPKey); err != nil {
			return []error{fmt.Errorf("%s: %w", l.DPoPKey, err)}
		}
	case c.DPoPKeyFile != "":
		if _, err := ReadDPoPKeyFile(c.DPoPKeyFile); err != nil {
			return []error{fmt.Errorf("%s: %w", l.DPoPKeyFile, err)}
		}
	case required:
		return []error{fmt.Errorf("%s is required (generate one with %s)", l.DPoPKey, DPoPKeyCommand)}
	}
	return nil
}

// RedirectURL is the OIDC callback URL to register with SystemAuth:
// PublicURL + BasePath + "/auth/callback".
func (c Config) RedirectURL() string {
	return strings.TrimRight(c.PublicURL, "/") + c.basePath() + "/auth/callback"
}

func (c Config) basePath() string {
	if c.BasePath == "" {
		return DefaultBasePath
	}
	return "/" + strings.Trim(c.BasePath, "/")
}

// acceptedClientIDs is AcceptedClientIDs with ClientID added, or nil when
// none are listed (relyingparty then accepts ClientID alone).
func (c Config) acceptedClientIDs() []string {
	if len(c.AcceptedClientIDs) == 0 {
		return nil
	}
	if slices.Contains(c.AcceptedClientIDs, c.ClientID) {
		return slices.Clone(c.AcceptedClientIDs)
	}
	return append([]string{c.ClientID}, c.AcceptedClientIDs...)
}

// insecureCookies is true exactly when the application is served over
// plain HTTP on a loopback host, for local development.
func (c Config) insecureCookies() bool {
	u, err := url.Parse(c.PublicURL)
	return err == nil && u.Scheme == "http" && IsLoopbackHost(u.Hostname())
}

// loopback reports whether PublicURL names a loopback host.
func (c Config) loopback() bool {
	u, err := url.Parse(c.PublicURL)
	return err == nil && IsLoopbackHost(u.Hostname())
}

func checkOrigin(label, raw string) error {
	u, err := parseURL(label, raw)
	if err != nil {
		return err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s must be an origin without a path, got %q", label, raw)
	}
	return nil
}

func parseURL(label, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%s must be an absolute URL, got %q", label, raw)
	}
	switch u.Scheme {
	case "https":
		return u, nil
	case "http":
		if IsLoopbackHost(u.Hostname()) {
			return u, nil
		}
		return nil, fmt.Errorf("%s must use https (http is allowed only for a loopback host), got %q", label, raw)
	default:
		return nil, fmt.Errorf("%s must be an http(s) URL, got %q", label, raw)
	}
}

// IsLoopbackHost reports whether host is localhost, a *.localhost name, or
// a loopback IP address.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// dpopKey returns the configured key, and false when none is set.
func (c Config) dpopKey() (*dpop.KeyPair, bool, error) {
	var k *dpop.KeyPair
	var err error
	switch {
	case c.DPoPKey != "":
		k, err = ParseDPoPKey(c.DPoPKey)
	case c.DPoPKeyFile != "":
		k, err = ReadDPoPKeyFile(c.DPoPKeyFile)
	default:
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	return k, true, nil
}
