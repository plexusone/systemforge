package authz

import (
	"strings"
	"testing"
)

func TestConfigDefaults(t *testing.T) {
	var c ModeConfig
	c.ApplyDefaults()
	if c.Mode != ModeRBAC || c.Engine != "" || c.SpiceDB != nil {
		t.Errorf("zero config defaults = %+v, want rbac only", c)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("rbac default: %v", err)
	}

	r := ModeConfig{Mode: ModeReBAC}
	r.ApplyDefaults()
	if r.Engine != EngineSpiceDB || r.SpiceDB == nil || r.SpiceDB.Mode != "embedded" || r.SpiceDB.DatastoreEngine != "memory" {
		t.Errorf("rebac defaults = %+v / %+v", r, r.SpiceDB)
	}
	if err := r.Validate(); err != nil {
		t.Errorf("rebac default: %v", err)
	}

	// Defaults do not override what is set.
	remote := ModeConfig{Mode: ModeReBAC, SpiceDB: &SpiceDBConfig{Mode: "remote", Endpoint: "spicedb:50051"}}
	remote.ApplyDefaults()
	if remote.SpiceDB.DatastoreEngine != "" {
		t.Errorf("remote got an embedded datastore default: %+v", remote.SpiceDB)
	}
	if err := remote.Validate(); err != nil {
		t.Errorf("remote: %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	for name, tc := range map[string]struct {
		cfg  ModeConfig
		want string // substring of the error; "" means valid
	}{
		"rbac":                 {ModeConfig{Mode: ModeRBAC}, ""},
		"unknown mode":         {ModeConfig{Mode: "abac"}, `unknown mode "abac"`},
		"empty mode":           {ModeConfig{}, "mode is empty"},
		"engine with rbac":     {ModeConfig{Mode: ModeRBAC, Engine: EngineSpiceDB}, "engines apply to mode rebac"},
		"spicedb with rbac":    {ModeConfig{Mode: ModeRBAC, SpiceDB: &SpiceDBConfig{}}, "mode is rbac"},
		"unknown engine":       {ModeConfig{Mode: ModeReBAC, Engine: "openfga", SpiceDB: &SpiceDBConfig{}}, `unknown engine "openfga"`},
		"no spicedb settings":  {ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB}, "needs its settings"},
		"unknown spicedb mode": {ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "sidecar"}}, `unknown spicedb.mode "sidecar"`},
		"remote without endpoint": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "remote"}}, "requires spicedb.endpoint"},
		"remote with datastore": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "remote", Endpoint: "x:1", DatastoreEngine: "postgres"}}, "apply to spicedb.mode embedded"},
		"embedded with endpoint": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "embedded", DatastoreEngine: "memory", Endpoint: "x:1"}}, "apply to spicedb.mode remote"},
		"postgres without uri": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "embedded", DatastoreEngine: "postgres"}}, "requires spicedb.datastore_uri"},
		"memory with uri": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "embedded", DatastoreEngine: "memory", DatastoreURI: "x"}}, "applies to datastore_engine postgres"},
		"unknown datastore": {
			ModeConfig{Mode: ModeReBAC, Engine: EngineSpiceDB, SpiceDB: &SpiceDBConfig{Mode: "embedded", DatastoreEngine: "mysql"}}, `unknown spicedb.datastore_engine "mysql"`},
	} {
		err := tc.cfg.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
}
