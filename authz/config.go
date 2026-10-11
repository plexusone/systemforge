package authz

import (
	"fmt"
	"slices"
)

// Mode names how a deployment evaluates authorization (ADR-008). The modes
// are named for the model they evaluate, not the technology.
type Mode string

const (
	// ModeRBAC is role-based: organization roles, application roles and
	// direct grants on resources, evaluated in process from the membership,
	// role and grant tables (package authz/rbac).
	ModeRBAC Mode = "rbac"

	// ModeReBAC is relationship-based: permissions derived through
	// relationships by an engine, which Engine selects (package
	// authz/rebac/<engine>).
	ModeReBAC Mode = "rebac"
)

// Engine names the relationship engine behind ModeReBAC.
type Engine string

// EngineSpiceDB is the SpiceDB engine, package authz/rebac/spicedb. It is
// the only engine today; another, such as OpenFGA, would sit beside it
// without changing this configuration's vocabulary.
const EngineSpiceDB Engine = "spicedb"

// Engines returns the relationship engines this version supports.
func Engines() []Engine { return []Engine{EngineSpiceDB} }

// ModeConfig is the authorization configuration of a deployment: the `authz`
// key of the SystemAuth configuration file.
//
//	authz:
//	  mode: rebac
//	  engine: spicedb
//	  spicedb:
//	    mode: remote
//	    endpoint: spicedb.internal:50051
//	    token: ${SPICEDB_TOKEN}
//
// ModeConfig only describes the choice. authz/mode.New builds the provider
// from it, because the providers import this package.
type ModeConfig struct {
	// Mode is "rbac" (the default) or "rebac".
	Mode Mode `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=rbac,enum=rebac,default=rbac,description=Authorization mode: rbac (roles and direct grants) or rebac (relationships evaluated by an engine)"`

	// Engine selects the relationship engine for mode rebac; default
	// "spicedb". It must be empty for mode rbac.
	Engine Engine `json:"engine,omitempty" yaml:"engine,omitempty" jsonschema:"enum=spicedb,description=Relationship engine for mode rebac (default spicedb)"`

	// SpiceDB configures the spicedb engine. Nil means an embedded
	// in-memory instance, for development and tests.
	SpiceDB *SpiceDBConfig `json:"spicedb,omitempty" yaml:"spicedb,omitempty" jsonschema:"description=SpiceDB engine settings for mode rebac"`
}

// SpiceDBConfig holds the settings of the SpiceDB engine. It is the
// configuration type of authz/rebac/spicedb (spicedb.Config is an alias),
// declared here so that loading configuration does not pull the SpiceDB
// server into every importer of this package.
type SpiceDBConfig struct {
	// Mode is how SpiceDB runs: "embedded" (in this process, the default)
	// or "remote" (a service reached over gRPC).
	Mode string `json:"mode,omitempty" yaml:"mode,omitempty" jsonschema:"enum=embedded,enum=remote,default=embedded,description=embedded (in process) or remote (gRPC service)"`

	// DatastoreEngine is the embedded datastore: "memory" (default) or
	// "postgres".
	DatastoreEngine string `json:"datastore_engine,omitempty" yaml:"datastore_engine,omitempty" jsonschema:"enum=memory,enum=postgres,default=memory,description=Embedded datastore"`

	// DatastoreURI is the connection string of the embedded postgres
	// datastore.
	DatastoreURI string `json:"datastore_uri,omitempty" yaml:"datastore_uri,omitempty" jsonschema:"description=Connection string of the embedded postgres datastore (supports env var expansion)"`

	// Endpoint is the gRPC address of a remote SpiceDB, "host:port".
	Endpoint string `json:"endpoint,omitempty" yaml:"endpoint,omitempty" jsonschema:"description=gRPC address of a remote SpiceDB"`

	// Token is the preshared key of a remote SpiceDB.
	Token string `json:"token,omitempty" yaml:"token,omitempty" jsonschema:"description=Preshared key of a remote SpiceDB (supports env var expansion)"` //nolint:gosec // G117: a configured credential, injected from the environment

	// Insecure skips TLS to a remote SpiceDB. Development only.
	Insecure bool `json:"insecure,omitempty" yaml:"insecure,omitempty" jsonschema:"default=false,description=Development only: connect to a remote SpiceDB without TLS"`

	// WriteSchema writes the composed schema (the base schema and every
	// registered vocabulary's fragment) to the engine at startup. An
	// embedded instance always gets it, since it starts empty; for a remote
	// one it is off by default, because a shared service's schema is an
	// operational decision.
	WriteSchema bool `json:"write_schema,omitempty" yaml:"write_schema,omitempty" jsonschema:"default=false,description=Write the composed schema to a remote SpiceDB at startup"`
}

// ApplyDefaults fills in the defaults: mode rbac; for rebac, engine spicedb
// with an embedded in-memory instance.
func (c *ModeConfig) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = ModeRBAC
	}
	if c.Mode != ModeReBAC {
		return
	}
	if c.Engine == "" {
		c.Engine = EngineSpiceDB
	}
	if c.Engine == EngineSpiceDB {
		if c.SpiceDB == nil {
			c.SpiceDB = &SpiceDBConfig{}
		}
		if c.SpiceDB.Mode == "" {
			c.SpiceDB.Mode = "embedded"
		}
		if c.SpiceDB.Mode == "embedded" && c.SpiceDB.DatastoreEngine == "" {
			c.SpiceDB.DatastoreEngine = "memory"
		}
	}
}

// Validate checks the configuration, after ApplyDefaults. The errors name
// the key and the accepted values.
func (c ModeConfig) Validate() error {
	switch c.Mode {
	case ModeRBAC:
		if c.Engine != "" {
			return fmt.Errorf("authz: engine %q is set but mode is rbac; engines apply to mode rebac", c.Engine)
		}
		if c.SpiceDB != nil {
			return fmt.Errorf("authz: spicedb settings are given but mode is rbac; they apply to mode rebac")
		}
		return nil
	case ModeReBAC:
	case "":
		return fmt.Errorf("authz: mode is empty (want rbac or rebac); call ApplyDefaults first")
	default:
		return fmt.Errorf("authz: unknown mode %q (want rbac or rebac)", c.Mode)
	}

	if !slices.Contains(Engines(), c.Engine) {
		return fmt.Errorf("authz: unknown engine %q for mode rebac (want %v)", c.Engine, Engines())
	}
	s := c.SpiceDB
	if s == nil {
		return fmt.Errorf("authz: engine spicedb needs its settings; call ApplyDefaults first")
	}
	switch s.Mode {
	case "embedded":
		if s.Endpoint != "" || s.Token != "" {
			return fmt.Errorf("authz: spicedb.endpoint and spicedb.token apply to spicedb.mode remote, not embedded")
		}
		switch s.DatastoreEngine {
		case "memory":
			if s.DatastoreURI != "" {
				return fmt.Errorf("authz: spicedb.datastore_uri applies to datastore_engine postgres, not memory")
			}
		case "postgres":
			if s.DatastoreURI == "" {
				return fmt.Errorf("authz: spicedb.datastore_engine postgres requires spicedb.datastore_uri")
			}
		default:
			return fmt.Errorf("authz: unknown spicedb.datastore_engine %q (want memory or postgres)", s.DatastoreEngine)
		}
	case "remote":
		if s.Endpoint == "" {
			return fmt.Errorf("authz: spicedb.mode remote requires spicedb.endpoint")
		}
		if s.DatastoreEngine != "" || s.DatastoreURI != "" {
			return fmt.Errorf("authz: spicedb.datastore_engine and spicedb.datastore_uri apply to spicedb.mode embedded, not remote")
		}
	default:
		return fmt.Errorf("authz: unknown spicedb.mode %q (want embedded or remote)", s.Mode)
	}
	return nil
}

// Provider is what a configured mode provides, whichever mode it is: the
// platform authorizer and the resource-grant contract. The role-based
// provider also implements DecisionAuthorizer; assert for it when a reason
// is wanted.
type Provider interface {
	PlatformAuthorizer
	ResourceGranter
}
