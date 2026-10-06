// Package main provides a standalone SystemAuth OAuth 2.0 / OpenID Connect server.
package main

import (
	"fmt"
	"os"
)

var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func main() {
	cmd := newRootCmd()
	cmd.SetArgs(normalizeArgs(os.Args[1:]))
	if err := cmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
