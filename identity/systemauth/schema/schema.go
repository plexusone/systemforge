// Package schema provides the embedded JSON Schema for SystemAuth configuration.
package schema

import (
	_ "embed"
)

//go:generate go run generate.go

// ConfigSchema is the JSON Schema for SystemAuth configuration.
// It can be used to validate configuration files in both YAML and JSON formats.
//
//go:embed config.schema.json
var ConfigSchema []byte

// SchemaID is the canonical URL for the schema.
const SchemaID = "https://github.com/plexusone/systemforge/identity/systemauth/config.schema.json"
