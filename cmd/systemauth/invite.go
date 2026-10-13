package main

import (
	"context"
	"errors"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/signupgate/signupcmd"
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
