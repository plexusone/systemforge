package systemauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/plexusone/systemforge/secrets"
)

// LoadConfig loads configuration from a file, applies defaults and
// validates it.
// Supports both YAML (.yaml, .yml) and JSON (.json) formats.
// The format is detected by file extension. Secret references are read
// from the vault named by secrets.vault, or the environment.
func LoadConfig(path string) (*Config, error) {
	return LoadConfigWithResolver(context.Background(), path, nil)
}

// LoadConfigWithResolver is LoadConfig reading secret references through
// r. A nil r uses the vault named by secrets.vault, or the environment.
func LoadConfigWithResolver(ctx context.Context, path string, r *secrets.Resolver) (*Config, error) {
	cfg, err := DecodeConfigFileWithResolver(ctx, path, r)
	if err != nil {
		return nil, err
	}
	return finishConfig(cfg)
}

// DecodeConfigFile reads and decodes the configuration file at path like
// LoadConfig, resolving secret references, but without applying
// defaults or validating, so a caller can adjust the result first (then
// call ApplyDefaults and Validate).
func DecodeConfigFile(path string) (*Config, error) {
	return DecodeConfigFileWithResolver(context.Background(), path, nil)
}

// DecodeConfigFileWithResolver is DecodeConfigFile reading secret
// references through r (nil: secrets.vault, or the environment).
func DecodeConfigFileWithResolver(ctx context.Context, path string, r *secrets.Resolver) (*Config, error) {
	//nolint:gosec // G304: Path is provided by the user/caller for config loading
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return DecodeConfigWithResolver(ctx, data, detectFormat(path), r)
}

// ConfigFormat represents a configuration file format.
type ConfigFormat string

const (
	// FormatYAML indicates YAML format.
	FormatYAML ConfigFormat = "yaml"
	// FormatJSON indicates JSON format.
	FormatJSON ConfigFormat = "json"
)

// detectFormat determines the config format from the file extension.
func detectFormat(path string) ConfigFormat {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		return FormatJSON
	case ".yaml", ".yml":
		return FormatYAML
	default:
		// Default to YAML
		return FormatYAML
	}
}

// ParseConfig parses configuration from bytes in the specified format,
// resolves secret references, applies defaults and validates it.
func ParseConfig(data []byte, format ConfigFormat) (*Config, error) {
	return ParseConfigWithResolver(context.Background(), data, format, nil)
}

// ParseConfigWithResolver is ParseConfig reading secret references
// through r (nil: secrets.vault, or the environment).
func ParseConfigWithResolver(ctx context.Context, data []byte, format ConfigFormat, r *secrets.Resolver) (*Config, error) {
	cfg, err := DecodeConfigWithResolver(ctx, data, format, r)
	if err != nil {
		return nil, err
	}
	return finishConfig(cfg)
}

// finishConfig applies defaults and validates a decoded configuration.
func finishConfig(cfg *Config) (*Config, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// DecodeConfig decodes configuration from bytes in the specified format
// and resolves secret references in it, without applying defaults or
// validating. Callers that adjust the configuration afterwards (e.g. to
// supply a missing issuer) then call ApplyDefaults and Validate.
func DecodeConfig(data []byte, format ConfigFormat) (*Config, error) {
	return DecodeConfigWithResolver(context.Background(), data, format, nil)
}

// DecodeConfigWithResolver is DecodeConfig reading secret references
// through r. A nil r opens the vault named by secrets.vault for the
// duration of the call, or reads the environment when none is named.
func DecodeConfigWithResolver(ctx context.Context, data []byte, format ConfigFormat, r *secrets.Resolver) (*Config, error) {
	var cfg Config

	switch format {
	case FormatJSON:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse JSON config: %w", err)
		}
	case FormatYAML:
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse YAML config: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", format)
	}

	if err := cfg.resolveSecrets(ctx, r); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// resolveSecrets resolves ${NAME} and $NAME references in the secret
// fields through r, or, when r is nil, the vault secrets.vault names (the
// environment by default).
func (c *Config) resolveSecrets(ctx context.Context, r *secrets.Resolver) (err error) {
	if r == nil {
		var owned *secrets.Resolver
		owned, err = c.secretsResolver()
		if err != nil {
			return err
		}
		defer func() {
			if cerr := owned.Close(); cerr != nil {
				err = errors.Join(err, fmt.Errorf("closing secrets vault: %w", cerr))
			}
		}()
		r = owned
	}
	e := expander{ctx: ctx, r: r}

	// Client secrets
	for i := range c.Clients {
		e.expand(&c.Clients[i].Secret)
	}

	// The authorization engine settings
	if c.Authz.SpiceDB != nil {
		e.expand(&c.Authz.SpiceDB.Token)
		e.expand(&c.Authz.SpiceDB.DatastoreURI)
		e.expand(&c.Authz.SpiceDB.Endpoint)
	}

	// Federation
	if c.Federation != nil {
		e.expand(&c.Federation.ClientID)
		e.expand(&c.Federation.ClientSecret)
	}

	// Social login provider credentials
	if c.SocialLogin != nil {
		for _, p := range []*SocialProviderConfig{c.SocialLogin.GitHub, c.SocialLogin.Google} {
			if p != nil {
				e.expand(&p.ClientID)
				e.expand(&p.ClientSecret)
			}
		}
	}

	// Signing and verification keys, token and DPoP secrets
	e.expand(&c.Keys.KeyID)
	e.expand(&c.Keys.PrivateKeyFile)
	e.expandWhole(&c.Keys.PrivateKeyPEM)
	e.expandWhole(&c.Tokens.HMACSecret)
	e.expandWhole(&c.Tokens.HMACVerificationSecret)
	e.expand(&c.DPoP.NonceSecret)
	e.expand(&c.DPoP.ReplayCacheRedisURL)
	for i := range c.Keys.VerificationKeys {
		v := &c.Keys.VerificationKeys[i]
		e.expand(&v.KeyID)
		e.expand(&v.PublicKeyFile)
		e.expandWhole(&v.PublicKeyPEM)
	}

	// Shared rate limit storage
	e.expand(&c.RateLimit.RedisURL)

	// Database DSN
	if c.Database != nil {
		e.expand(&c.Database.DSN)
	}
	return e.err
}

// secretsResolver opens the vault secrets.vault names (its own value read
// from the environment), or the environment when none is named.
func (c *Config) secretsResolver() (*secrets.Resolver, error) {
	if c.Secrets == nil || c.Secrets.Vault == "" {
		return secrets.Env(), nil
	}
	uri := os.ExpandEnv(c.Secrets.Vault)
	if uri == "" {
		return secrets.Env(), nil
	}
	r, err := secrets.FromURI(uri)
	if err != nil {
		return nil, fmt.Errorf("secrets.vault: %w", err)
	}
	return r, nil
}

// expander resolves fields in place, keeping the first error.
type expander struct {
	ctx context.Context
	r   *secrets.Resolver
	err error
}

func (e *expander) expand(p *string) {
	if e.err != nil {
		return
	}
	*p, e.err = e.r.Expand(e.ctx, *p)
}

func (e *expander) expandWhole(p *string) {
	if e.err != nil {
		return
	}
	*p, e.err = e.r.ExpandWhole(e.ctx, *p)
}

// SaveConfig saves configuration to a file.
// The format is determined by the file extension.
func SaveConfig(cfg *Config, path string) error {
	format := detectFormat(path)

	var data []byte
	var err error

	switch format {
	case FormatJSON:
		data, err = json.MarshalIndent(cfg, "", "  ")
	case FormatYAML:
		data, err = yaml.Marshal(cfg)
	default:
		return fmt.Errorf("unsupported config format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
