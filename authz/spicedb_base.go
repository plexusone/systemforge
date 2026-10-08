package authz

import (
	"fmt"
	"strings"
)

// BaseSpiceDBSchema is the SystemForge-owned foundation of every composed
// ReBAC deployment: principals, the organization membership ladder, and the
// platform. Applications never redefine these; they attach via an
// "{app}_org" facet definition that references organization and adds the
// app's domain roles (see docs/authz-conventions.md for the pattern and a
// worked example).
const BaseSpiceDBSchema = `
// =============================================================================
// SYSTEMFORGE BASE — owned by the platform; applications must not redefine
// these. Apps attach through "{app}_org" facet definitions.
// =============================================================================

definition principal {
    // Manager relations (ADR-005): a guardian or educator manages this
    // principal. Applications add domain permissions in their facets.
    relation guardian: principal
    relation educator: principal

    permission manage_account     = guardian
    permission manage_credentials = guardian + educator
    permission view_profile       = guardian + educator
    permission manage_managers    = guardian
}

definition organization {
    relation owner: principal
    relation admin: principal
    relation editor: principal
    relation member: principal
    relation viewer: principal

    // Generic ladder mirroring the simple provider's DefaultRoleHierarchy.
    permission manage = owner + admin
    permission edit = manage + editor
    permission contribute = edit + member
    permission view = contribute + viewer

    // Org administration.
    permission invite_member = manage
    permission remove_member = manage
    permission change_role = manage
    permission settings = manage
    permission delete = owner
}

definition platform {
    relation admin: principal
    permission super_admin = admin
}
`

// baseDefinitions are the reserved names owned by the base schema.
func baseDefinitions() []string {
	return findSchemaDefinitions(BaseSpiceDBSchema)
}

// ComposeSpiceDBSchema assembles the deployment's full SpiceDB schema: the
// SystemForge base followed by every registered app's fragment in
// registration order. It fails on any duplicate definition — impossible when
// fragments follow the "{app}_" prefix convention, but verified anyway so a
// bad fragment cannot silently shadow another app's (or the base's)
// definitions.
func (r *VocabularyRegistry) ComposeSpiceDBSchema() (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	seen := map[string]string{} // definition -> owner
	for _, name := range baseDefinitions() {
		seen[name] = "systemforge base"
	}

	var b strings.Builder
	b.WriteString(strings.TrimSpace(BaseSpiceDBSchema))
	b.WriteString("\n")

	for _, app := range r.order {
		fragment := r.apps[app].SpiceDBSchema()
		if strings.TrimSpace(fragment) == "" {
			continue
		}
		for _, name := range findSchemaDefinitions(fragment) {
			if owner, dup := seen[name]; dup {
				return "", fmt.Errorf("authz: definition %q from app %q already defined by %s", name, app, owner)
			}
			seen[name] = "app " + app
		}
		b.WriteString("\n")
		b.WriteString(strings.TrimSpace(fragment))
		b.WriteString("\n")
	}
	return b.String(), nil
}
