package authz

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// AppVocabulary is the authorization vocabulary a Forge application registers
// with the platform: its roles, permissions, OAuth scopes, and (optionally)
// its SpiceDB schema fragment. Registering a vocabulary is what makes an app
// administrable — the IAM console renders roles/permissions/scopes directly
// from the registry, and the composed SpiceDB schema is assembled from the
// registered fragments.
//
// Conventions (normative; see docs/authz-conventions.md):
//
//   - App names are short lowercase identifiers ("actionforge").
//   - Scopes are "{app}:{resource}:{verb}" plus the blanket "{app}:admin".
//   - Application roles are the application's own (for example
//     "viewer", "editor", "approver") and must appear in both Roles() and
//     Hierarchy(). They are distinct from organization roles (owner, admin,
//     member, collaborator) and from resource roles (viewer, contributor,
//     maintainer on a resource).
//   - SpiceDB fragments define only "{app}_"-prefixed definitions and attach
//     to the shared base definitions (principal, organization, platform) via
//     an "{app}_org" facet — never by redefining the base.
type AppVocabulary interface {
	// App returns the application identifier (e.g. "actionforge").
	App() string
	// Roles maps each role name to its granted dotted permissions.
	Roles() RolePermissions
	// Hierarchy orders the app's roles; every role in Roles() must appear.
	Hierarchy() RoleHierarchy
	// Scopes lists every OAuth scope the app defines.
	Scopes() []string
	// SpiceDBSchema returns the app's ReBAC schema fragment, or "" if the app
	// only supports the role-based (rbac) provider.
	SpiceDBSchema() string
}

var (
	appNameRe  = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)
	scopeRe    = regexp.MustCompile(`^([a-z][a-z0-9]*):([a-z][a-z0-9-]*):([a-z][a-z0-9-]*)$`)
	adminRe    = regexp.MustCompile(`^([a-z][a-z0-9]*):admin$`)
	spiceDefRe = regexp.MustCompile(`\bdefinition\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

// findSchemaDefinitions returns every "definition NAME" declared in a SpiceDB
// schema fragment. It strips "//" line comments first and matches on a word
// boundary rather than line position — a fragment that packs more than one
// definition onto a single physical line (e.g. "definition a {} definition
// b {}") must not let the second one evade detection, since callers rely on
// this to reject schema fragments that redefine reserved or foreign names.
func findSchemaDefinitions(schema string) []string {
	stripped := stripSchemaComments(schema)

	var names []string
	for _, m := range spiceDefRe.FindAllStringSubmatch(stripped, -1) {
		names = append(names, m[1])
	}
	return names
}

// stripSchemaComments removes "//" line comments from a schema fragment.
func stripSchemaComments(schema string) string {
	lines := strings.Split(schema, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// schemaDefinition is one definition of a schema fragment: its name and
// the relations it declares, relation name to the allowed subject types as
// written ("principal", "principal | team#member").
type schemaDefinition struct {
	name      string
	relations map[string]string
}

var (
	relationStartRe = regexp.MustCompile(`\b(relation|permission)\s+\w+\s*[:=]`)
	relationRe      = regexp.MustCompile(`^relation\s+(\w+)\s*:\s*(.*?)\s*$`)
)

// parseSchemaDefinitions returns the definitions of a fragment with their
// relations. It is a scanner for the conventions this package validates,
// not a SpiceDB parser: bodies are found by brace matching and each
// relation is read up to the next relation or permission, so fragments
// that pack several statements on a line are read as written.
func parseSchemaDefinitions(schema string) []schemaDefinition {
	stripped := stripSchemaComments(schema)
	var out []schemaDefinition
	for _, loc := range spiceDefRe.FindAllStringSubmatchIndex(stripped, -1) {
		name := stripped[loc[2]:loc[3]]
		open := strings.Index(stripped[loc[1]:], "{")
		if open < 0 {
			continue
		}
		start := loc[1] + open + 1
		depth, end := 1, len(stripped)
		for i := start; i < len(stripped); i++ {
			switch stripped[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
			if depth == 0 {
				end = i
				break
			}
		}
		body := stripped[start:end]
		// One statement per line, so a packed body reads like a spread one.
		body = relationStartRe.ReplaceAllStringFunc(body, func(m string) string { return "\n" + m })
		def := schemaDefinition{name: name, relations: map[string]string{}}
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if m := relationRe.FindStringSubmatch(line); m != nil {
				def.relations[m[1]] = strings.Join(strings.Fields(m[2]), " ")
			}
		}
		out = append(out, def)
	}
	return out
}

// declaresResourceRoles reports which of the resource-role relations a
// definition declares.
func (d schemaDefinition) declaresResourceRoles() (declared, missing []string) {
	for _, role := range resourceRoles {
		if _, ok := d.relations[role]; ok {
			declared = append(declared, role)
		} else {
			missing = append(missing, role)
		}
	}
	return declared, missing
}

// CollaboratorDefinitions returns the definitions of a schema fragment that
// accept collaborators: those declaring the whole resource-role ladder
// (viewer, contributor, maintainer).
func CollaboratorDefinitions(schema string) []string {
	var out []string
	for _, d := range parseSchemaDefinitions(schema) {
		if _, missing := d.declaresResourceRoles(); len(missing) == 0 {
			out = append(out, d.name)
		}
	}
	return out
}

// validateCollaboratorDefinitions checks the definitions that use the
// reserved resource-role names (ADR-008): a definition that declares any of
// viewer, contributor and maintainer declares all three, binds each to
// principal, and has an org relation to organization, so that every
// application means the same thing by the ladder and a collaborator's
// access composes with the organization's.
func validateCollaboratorDefinitions(schema string) error {
	for _, d := range parseSchemaDefinitions(schema) {
		declared, missing := d.declaresResourceRoles()
		if len(declared) == 0 {
			continue
		}
		if len(missing) > 0 {
			return fmt.Errorf("authz: SpiceDB definition %q declares %s but not %s; the resource roles viewer, contributor and maintainer are reserved and must be declared together",
				d.name, strings.Join(declared, ", "), strings.Join(missing, ", "))
		}
		for _, role := range resourceRoles {
			if d.relations[role] != "principal" {
				return fmt.Errorf("authz: SpiceDB definition %q relation %q must be of type principal, not %q", d.name, role, d.relations[role])
			}
		}
		if d.relations["org"] != "organization" {
			return fmt.Errorf("authz: SpiceDB definition %q accepts collaborators and must declare `relation org: organization`", d.name)
		}
	}
	return nil
}

// ValidateScope checks one scope against the "{app}:{resource}:{verb}" (or
// "{app}:admin") convention for the given app.
func ValidateScope(app, scope string) error {
	if m := adminRe.FindStringSubmatch(scope); m != nil {
		if m[1] != app {
			return fmt.Errorf("authz: scope %q admin prefix %q does not match app %q", scope, m[1], app)
		}
		return nil
	}
	m := scopeRe.FindStringSubmatch(scope)
	if m == nil {
		return fmt.Errorf("authz: scope %q does not match {app}:{resource}:{verb}", scope)
	}
	if m[1] != app {
		return fmt.Errorf("authz: scope %q prefix %q does not match app %q", scope, m[1], app)
	}
	return nil
}

// ValidateAppSchema checks an app's SpiceDB fragment: every definition it
// declares must be prefixed "{app}_", so fragments can never collide with the
// shared base definitions or with another app, and a definition using the
// reserved resource-role names must declare the whole ladder (see
// validateCollaboratorDefinitions). An empty schema is valid.
func ValidateAppSchema(app, schema string) error {
	for _, name := range findSchemaDefinitions(schema) {
		if !strings.HasPrefix(name, app+"_") {
			return fmt.Errorf("authz: SpiceDB definition %q must be prefixed %q", name, app+"_")
		}
	}
	return validateCollaboratorDefinitions(schema)
}

// ValidateVocabulary checks a vocabulary against every convention: app name
// format, scope format and prefix, hierarchy covering all roles, and schema
// definition prefixing.
func ValidateVocabulary(v AppVocabulary) error {
	app := v.App()
	if !appNameRe.MatchString(app) {
		return fmt.Errorf("authz: invalid app name %q (want short lowercase identifier)", app)
	}
	roles := v.Roles()
	if len(roles) == 0 {
		return fmt.Errorf("authz: app %q registers no roles", app)
	}
	h := v.Hierarchy()
	for role := range roles {
		if _, ok := h[role]; !ok {
			return fmt.Errorf("authz: app %q role %q missing from hierarchy", app, role)
		}
	}
	seen := map[string]bool{}
	for _, s := range v.Scopes() {
		if err := ValidateScope(app, s); err != nil {
			return err
		}
		if seen[s] {
			return fmt.Errorf("authz: app %q declares scope %q twice", app, s)
		}
		seen[s] = true
	}
	return ValidateAppSchema(app, v.SpiceDBSchema())
}

// VocabularyRegistry holds the vocabularies of every app in a deployment. A
// composed deployment registers each Forge app at startup; registration
// validates the vocabulary so convention drift fails fast rather than
// surfacing as authorization bugs.
type VocabularyRegistry struct {
	mu    sync.RWMutex
	apps  map[string]AppVocabulary
	order []string
}

// NewVocabularyRegistry returns an empty registry.
func NewVocabularyRegistry() *VocabularyRegistry {
	return &VocabularyRegistry{apps: map[string]AppVocabulary{}}
}

// Register validates and adds an app's vocabulary. Registering the same app
// twice is an error.
func (r *VocabularyRegistry) Register(v AppVocabulary) error {
	if err := ValidateVocabulary(v); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	app := v.App()
	if _, dup := r.apps[app]; dup {
		return fmt.Errorf("authz: app %q already registered", app)
	}
	r.apps[app] = v
	r.order = append(r.order, app)
	return nil
}

// Apps returns the registered app names in registration order.
func (r *VocabularyRegistry) Apps() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]string(nil), r.order...)
}

// Get returns the vocabulary registered for app.
func (r *VocabularyRegistry) Get(app string) (AppVocabulary, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.apps[app]
	return v, ok
}

// AllScopes returns every registered scope, sorted, for consent screens and
// principal AllowedScopes configuration.
func (r *VocabularyRegistry) AllScopes() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []string
	for _, app := range r.order {
		out = append(out, r.apps[app].Scopes()...)
	}
	sort.Strings(out)
	return out
}
