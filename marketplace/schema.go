package marketplace

import (
	_ "embed"

	"github.com/plexusone/systemforge/authz"
)

// MarketplaceSchema is the marketplace's SpiceDB schema fragment. It does
// not stand alone: it attaches to the "principal" and "organization"
// definitions of authz.BaseSpiceDBSchema through the marketplace_org facet,
// as the vocabulary rules require. Use MergeSchema to compose it.
//
//go:embed schema/marketplace.zed
var MarketplaceSchema string

// MergeSchema composes the SystemForge base schema, the marketplace schema
// and an application-specific schema. The app schema should define
// app-specific resource types that reference marketplace types (listing,
// license, etc.).
func MergeSchema(appSchema string) string {
	return authz.BaseSpiceDBSchema + "\n\n" + MarketplaceSchema + "\n\n" + appSchema
}
