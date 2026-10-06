package systemauth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads configuration from a file.
// Supports both YAML (.yaml, .yml) and JSON (.json) formats.
// The format is detected by file extension.
func LoadConfig(path string) (*Config, error) {
	//nolint:gosec // G304: Path is provided by the user/caller for config loading
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return ParseConfig(data, detectFormat(path))
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

// ParseConfig parses configuration from bytes in the specified format.
func ParseConfig(data []byte, format ConfigFormat) (*Config, error) {
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

	// Expand environment variables in sensitive fields
	cfg.expandEnvVars()

	// Apply defaults
	cfg.ApplyDefaults()

	// Validate
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// expandEnvVars expands environment variables in config values.
// Supports ${VAR} and $VAR syntax.
func (c *Config) expandEnvVars() {
	// Expand in client secrets
	for i := range c.Clients {
		c.Clients[i].Secret = os.ExpandEnv(c.Clients[i].Secret)
	}

	// Expand in federation config
	if c.Federation != nil {
		c.Federation.ClientID = os.ExpandEnv(c.Federation.ClientID)
		c.Federation.ClientSecret = os.ExpandEnv(c.Federation.ClientSecret)
	}

	// Expand in social login provider credentials
	if c.SocialLogin != nil {
		for _, p := range []*SocialProviderConfig{c.SocialLogin.GitHub, c.SocialLogin.Google} {
			if p != nil {
				p.ClientID = os.ExpandEnv(p.ClientID)
				p.ClientSecret = os.ExpandEnv(p.ClientSecret)
			}
		}
	}

	// Expand in database DSN
	if c.Database != nil {
		c.Database.DSN = os.ExpandEnv(c.Database.DSN)
	}
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
