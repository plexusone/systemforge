//go:build ignore

// This file generates JSON Schema from the Config struct.
// Run with: go generate ./...
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"reflect"

	"github.com/invopop/jsonschema"
	"github.com/plexusone/systemforge/identity/systemauth"
)

func main() {
	// Create a reflector with custom options
	r := &jsonschema.Reflector{
		DoNotReference:             true,
		ExpandedStruct:             true,
		RequiredFromJSONSchemaTags: true,
		// Types from other packages are named with their package, so one
		// called Config (clientaddr.Config) cannot stand in for
		// systemauth.Config.
		Namer: func(t reflect.Type) string {
			if t.PkgPath() != reflect.TypeFor[systemauth.Config]().PkgPath() {
				return path.Base(t.PkgPath()) + "." + t.Name()
			}
			return t.Name()
		},
	}

	// Generate schema from Config struct
	schema := r.Reflect(&systemauth.Config{})

	// Set schema metadata
	schema.ID = "https://github.com/plexusone/systemforge/identity/systemauth/config.schema.json"
	schema.Title = "SystemAuth Configuration"
	schema.Description = "Configuration schema for SystemAuth OAuth 2.0 / OpenID Connect server"

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(schema, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling schema: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	if err := os.WriteFile("config.schema.json", data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated config.schema.json")
}
