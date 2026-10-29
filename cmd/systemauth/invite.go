package main

import (
	"context"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/organization/membercmd"
	"github.com/plexusone/systemforge/identity/principal/admincmd"
	"github.com/plexusone/systemforge/identity/serviceaccount/serviceaccountcmd"
	"github.com/plexusone/systemforge/identity/signupgate/signupcmd"
	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// newInviteCmd builds "systemauth invite" (signupcmd) over the configured
// database, for a deployment served with --invite-only.
func newInviteCmd(opts *options) *cobra.Command { return signupcmd.InviteCommand(openDatabase(opts)) }

// newWaitlistCmd builds "systemauth waitlist" (signupcmd) over the
// configured database.
func newWaitlistCmd(opts *options) *cobra.Command {
	return signupcmd.WaitlistCommand(openDatabase(opts))
}

// newCodeCmd builds "systemauth code" (signupcmd) over the configured
// database, printing invite links on the issuer's /signup page.
func newCodeCmd(opts *options) *cobra.Command {
	return signupcmd.CodeCommand(openDatabase(opts), func() string {
		cfg, err := loadConfig(opts)
		if err != nil {
			// The command opened the database with this configuration
			// already, so it loads; without it, the link is left out.
			return ""
		}
		return strings.TrimRight(cfg.Issuer, "/") + systemauth.SignupPath
	})
}

// newAllowanceCmd builds "systemauth allowance" (signupcmd) over the
// configured database.
func newAllowanceCmd(opts *options) *cobra.Command {
	return signupcmd.AllowanceCommand(openDatabase(opts))
}

// newAdminCmd builds "systemauth admin" (admincmd) over the configured
// database.
func newAdminCmd(opts *options) *cobra.Command {
	return admincmd.Command(admincmd.Open(openDatabase(opts)))
}

// newOrgCmd builds "systemauth org member" (membercmd) over the configured
// database. Like service-account, the standalone server registers no role
// vocabularies, so it manages memberships; a host that embeds SystemAuth
// mounts membercmd with its own to grant application roles.
func newOrgCmd(opts *options) *cobra.Command {
	return membercmd.Command(membercmd.Open(openDatabase(opts)), membercmd.Options{})
}

// newServiceAccountCmd builds "systemauth service-account"
// (serviceaccountcmd) over the configured database. The standalone server
// hosts no applications, so it registers no role vocabularies: a host that
// embeds SystemAuth mounts the command with its own to grant roles.
func newServiceAccountCmd(opts *options) *cobra.Command {
	return serviceaccountcmd.Command(serviceaccountcmd.Open(openDatabase(opts)), serviceaccountcmd.Options{
		Issuer: func() string {
			cfg, err := loadConfig(opts)
			if err != nil {
				// The command opened the database with this configuration
				// already, so it loads; without it, the issuer is left out.
				return ""
			}
			return cfg.Issuer
		},
	})
}

// openDatabase opens the database the flags and configuration file name.
func openDatabase(opts *options) signupcmd.Open {
	return func(context.Context) (*ent.Client, func() error, error) {
		cfg, err := loadConfig(opts)
		if err != nil {
			return nil, nil, err
		}
		if cfg.Database == nil {
			return nil, nil, errors.New("this command reads the database: set --db-driver and --db-dsn (or a database in the config file)")
		}
		db, err := systemauthsvc.OpenDatabase(cfg.Database)
		if err != nil {
			return nil, nil, err
		}
		return db.Client, db.Close, nil
	}
}
