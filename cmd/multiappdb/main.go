// Command multiappdb provisions and checks the per-app database logins of a
// multiapp deployment.
//
//	multiappdb sql    --owner sf_owner --app example --role app_example_login
//	multiappdb apply  --owner sf_owner --app example --role app_example_login \
//	                  --admin-url-env ADMIN_DATABASE_URL --password-env EXAMPLE_DB_PASSWORD
//	multiappdb verify --owner sf_owner --login example=EXAMPLE_DATABASE_URL --login other=OTHER_DATABASE_URL
//
// Connection strings and passwords are read from environment variables
// named on the command line, never from arguments, so they stay out of
// shell history and process listings. Nothing secret is printed.
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
