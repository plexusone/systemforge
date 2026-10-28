package appauth_test

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/plexusone/systemforge/identity/appauth"
	"github.com/plexusone/systemforge/identity/relyingparty/pgstore"
	"github.com/plexusone/systemforge/identity/requestprincipal"
)

// An application reads its sign-in settings from APP_* variables, keeps
// sessions and principals in Postgres, and protects its API.
func Example() {
	ctx := context.Background()
	cfg, labels := appauth.ConfigFromEnv("APP")
	if err := cfg.Validate(labels); err != nil {
		log.Fatal(err)
	}
	db, err := sql.Open("pgx", "postgres://app@db.example.com/app")
	if err != nil {
		log.Fatal(err)
	}
	if err := pgstore.EnsureSchema(ctx, db); err != nil {
		log.Fatal(err)
	}
	stores, err := pgstore.NewStores(db, pgstore.KeysFromEnv("APP"))
	if err != nil {
		log.Fatal(err)
	}
	auth, err := appauth.New(ctx, cfg, appauth.Options{
		Principals:  stores.Principals,
		Sessions:    stores.Sessions,
		LoginStates: stores.LoginStates,
		Application: "notes",
		Labels:      &labels,
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle(auth.BasePath()+"/", auth.Handler())
	mux.Handle(appauth.ResourceMetadataPath, auth.ResourceMetadataHandler())
	mux.Handle("/api/", auth.Middleware(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := requestprincipal.FromContext(r.Context()) // set by Middleware(true)
		if _, err := fmt.Fprintf(w, "hello %s", p.PrincipalID); err != nil {
			log.Print(err)
		}
	})))
	log.Fatal(http.ListenAndServe(":8080", mux)) //nolint:gosec // G114: an example
}
