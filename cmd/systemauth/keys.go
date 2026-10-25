package main

import (
	"context"
	"errors"
	"os"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const acceptRollbackLong = `Open the connections keyring once, accepting it although this host has
recorded a newer generation or cannot verify the generation it has seen,
then exit.

Run it, with the server stopped, after:

  - restoring the keys directory from a backup,
  - moving the keys directory to a new host without its rollback state, or
  - upgrading from a release whose rollback state was not authenticated.

Accepting an older keyring brings back the key versions it holds, including
versions retired since the backup was taken. Confirm the keyring is the one
you mean to keep, then pass --confirm.`

// newKeysCmd returns the keys command group.
func newKeysCmd(opts *options) *cobra.Command {
	keysCmd := &cobra.Command{
		Use:   "keys",
		Short: "Manage the connections key system",
	}
	var confirm bool
	accept := &cobra.Command{
		Use:   "accept-rollback",
		Short: "Accept the connections keyring once after a restore, move or upgrade",
		Long:  acceptRollbackLong,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !confirm {
				return errors.New("accepting a keyring rollback restores the key versions it holds; pass --confirm after checking it is the keyring to keep")
			}
			return runAcceptRollback(cmd.Context(), opts)
		},
	}
	accept.Flags().BoolVar(&confirm, "confirm", false, "confirm the keyring is the one to keep")
	keysCmd.AddCommand(accept)
	return keysCmd
}

// runAcceptRollback opens the configured connections keyring once with
// rollback accepted.
func runAcceptRollback(ctx context.Context, opts *options) error {
	logger, err := systemauthsvc.NewLogger(os.Stdout, opts.logLevel, opts.logFormat)
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadConfig(opts)
	if err != nil {
		return err
	}
	if err := systemauthsvc.AcceptKeyRollback(ctx, cfg, logger); err != nil {
		return err
	}
	logger.Info("connections keyring accepted")
	return nil
}
