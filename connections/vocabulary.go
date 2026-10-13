package connections

import (
	"github.com/plexusone/systemforge/authz"
)

// App is the application identifier of the platform's own resources, the
// prefix of [ResourceType] ("systemforge_connection") and of the scopes of
// its API.
const App = "systemforge"

// vocabulary is the platform's registration of connections as a resource
// type, so that grants on a connection (ADR-008) are accepted when the
// deployment restricts grants to registered applications.
type vocabulary struct{}

// Vocabulary returns the application vocabulary of the connections API. It
// declares the resource type "systemforge_connection" (which takes viewer,
// contributor and maintainer grants) and the scopes
// "systemforge:connections:read" and "systemforge:connections:write". It
// declares no relationship-engine fragment: connections are served in the
// role-based mode.
func Vocabulary() authz.AppVocabulary { return vocabulary{} }

func (vocabulary) App() string { return App }

// Roles has one application role so the vocabulary validates; connections
// are governed by organization roles and resource grants, not by an
// application role.
func (vocabulary) Roles() authz.RolePermissions {
	return authz.RolePermissions{"manager": {"connections.manage"}}
}

func (vocabulary) Hierarchy() authz.RoleHierarchy { return authz.RoleHierarchy{"manager": 1} }

func (vocabulary) Scopes() []string { return []string{ScopeRead, ScopeWrite} }

func (vocabulary) SpiceDBSchema() string { return "" }

// RegisterVocabulary adds [Vocabulary] to reg unless the deployment has
// already registered an application named [App]. It is idempotent.
func RegisterVocabulary(reg *authz.VocabularyRegistry) error {
	if reg == nil {
		return nil
	}
	if _, ok := reg.Get(App); ok {
		return nil
	}
	return reg.Register(Vocabulary())
}
