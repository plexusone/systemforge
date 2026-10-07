package systemauthsvc

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/plexusone/systemforge/identity/systemauth"
)

// Config is the SystemAuth server configuration.
type Config = systemauth.Config

// ErrNotProductionReady is returned by New and CheckProduction when the
// configuration does not meet the production requirements and
// Options.Dev is not set.
var ErrNotProductionReady = errors.New("systemauthsvc: refusing to start in production mode")

// Override adjusts a loaded configuration before defaults and validation
// are applied, e.g. from command-line flags or environment variables.
type Override func(*Config) error

// WithIssuer sets the public issuer URL.
func WithIssuer(issuer string) Override {
	return func(c *Config) error {
		if issuer != "" {
			c.Issuer = issuer
		}
		return nil
	}
}

// WithDefaultIssuer sets the issuer only when the configuration has none,
// e.g. a localhost URL in development.
func WithDefaultIssuer(issuer string) Override {
	return func(c *Config) error {
		if c.Issuer == "" {
			c.Issuer = issuer
		}
		return nil
	}
}

// WithDatabase sets the database driver ("postgres" or "sqlite") and DSN.
// Environment variables in the DSN are expanded. Both must be given
// together; when both are empty the override does nothing.
func WithDatabase(driver, dsn string) Override {
	return func(c *Config) error {
		if driver == "" && dsn == "" {
			return nil
		}
		if driver == "" || dsn == "" {
			return errors.New("database driver and DSN must be set together")
		}
		c.Database = &systemauth.DatabaseConfig{Driver: driver, DSN: os.ExpandEnv(dsn)}
		return nil
	}
}

// WithSigningKeyFile sets the PEM RSA signing key file, replacing any
// configured key.
func WithSigningKeyFile(path string) Override {
	return func(c *Config) error {
		if path != "" {
			c.Keys.PrivateKeyFile = path
			c.Keys.PrivateKeyPEM = ""
		}
		return nil
	}
}

// WithDefaultSigningKeyPEM sets a PEM RSA signing key only when the
// configuration supplies none, e.g. from a secret injected through the
// environment.
func WithDefaultSigningKeyPEM(pem string) Override {
	return func(c *Config) error {
		if pem != "" && !c.Keys.HasSigningKey() {
			c.Keys.PrivateKeyPEM = pem
		}
		return nil
	}
}

// WithKeyID sets the JWKS key ID ("kid"). The default is the RFC 7638
// thumbprint of the signing key.
func WithKeyID(kid string) Override {
	return func(c *Config) error {
		if kid != "" {
			c.Keys.KeyID = kid
		}
		return nil
	}
}

// LoadConfig reads the configuration file at path (YAML or JSON by
// extension, with environment variable expansion; an empty path starts
// from an empty configuration), applies the overrides in order, then
// applies defaults and validates the result. Validation runs after the
// overrides, so an override can supply a value the file omits (e.g.
// WithDefaultIssuer).
func LoadConfig(path string, overrides ...Override) (*Config, error) {
	cfg := &Config{}
	if path != "" {
		c, err := systemauth.DecodeConfigFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		cfg = c
	}
	return finishConfig(cfg, overrides)
}

// LoadConfigBytes is LoadConfig for configuration already in memory, e.g.
// a section embedded in a host's own configuration file. format is "yaml"
// (or "yml") or "json"; an empty format detects JSON when the first
// non-space byte is '{' and YAML otherwise. Empty data starts from an
// empty configuration.
func LoadConfigBytes(data []byte, format string, overrides ...Override) (*Config, error) {
	f, err := configFormat(data, format)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if len(bytes.TrimSpace(data)) > 0 {
		c, err := systemauth.DecodeConfig(data, f)
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}
		cfg = c
	}
	return finishConfig(cfg, overrides)
}

func configFormat(data []byte, format string) (systemauth.ConfigFormat, error) {
	switch strings.ToLower(format) {
	case "yaml", "yml":
		return systemauth.FormatYAML, nil
	case "json":
		return systemauth.FormatJSON, nil
	case "":
		if t := bytes.TrimSpace(data); len(t) > 0 && t[0] == '{' {
			return systemauth.FormatJSON, nil
		}
		return systemauth.FormatYAML, nil
	default:
		return "", fmt.Errorf("unsupported config format %q (want yaml or json)", format)
	}
}

func finishConfig(cfg *Config, overrides []Override) (*Config, error) {
	for _, o := range overrides {
		if err := o(cfg); err != nil {
			return nil, err
		}
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}
	return cfg, nil
}

// CheckProduction reports, as an error wrapping ErrNotProductionReady,
// every production requirement the configuration and options miss: a
// signing key, a public https issuer, a persistent database and secure
// login cookies. It returns nil when opts.Dev is set.
func CheckProduction(cfg *Config, opts Options) error {
	if opts.Dev {
		return nil
	}
	var problems []string
	if !cfg.Keys.HasSigningKey() && opts.SigningKey == nil {
		problems = append(problems, "a signing key is required (keys.private_key_file, keys.private_key_pem or a programmatic key)")
	}
	if u, err := url.Parse(cfg.Issuer); err != nil || u.Scheme != "https" || u.Host == "" {
		problems = append(problems, "the issuer must be a public https URL")
	}
	if cfg.Database == nil && opts.DB == nil && opts.EntClient == nil {
		problems = append(problems, "a persistent database is required (database configuration or an injected database)")
	}
	if cfg.SocialLogin != nil && cfg.SocialLogin.InsecureCookies {
		problems = append(problems, "social_login.insecure_cookies is not allowed")
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrNotProductionReady, strings.Join(problems, "; "))
	}
	return nil
}
