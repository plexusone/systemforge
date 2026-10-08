//go:build ignore

package main

import (
	"log"

	"entgo.io/ent/entc"
	"entgo.io/ent/entc/gen"
)

func main() {
	err := entc.Generate("./schema", &gen.Config{
		Package: "github.com/plexusone/systemforge/identity/ent",
		Features: []gen.Feature{
			gen.FeatureUpsert,
			gen.FeaturePrivacy,
			gen.FeatureEntQL,
			gen.FeatureSnapshot,
			gen.FeatureExecQuery,
		},
	})
	if err != nil {
		log.Fatalf("running ent codegen: %v", err)
	}
}
