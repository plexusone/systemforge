package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/signupgate"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// newInviteCmd builds "systemauth invite": manage the sign-up invites that
// an invite-only deployment (--invite-only) checks. The commands open the
// configured database directly, so they work whether or not the server is
// running.
func newInviteCmd(opts *options) *cobra.Command {
	invite := &cobra.Command{
		Use:   "invite",
		Short: "Manage sign-up invites for an invite-only deployment",
		Long: `Manage the email addresses allowed to create an account while the
deployment runs with --invite-only. An invite is an address, not a code: the
person signs in with the upstream provider, and the account is created when
that provider's verified email matches an invite. People who already have an
account are not affected.`,
	}

	var (
		note      string
		invitedBy string
		expires   time.Duration
	)
	add := &cobra.Command{
		Use:   "add <email>...",
		Short: "Invite one or more email addresses",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var exp *time.Time
			if expires > 0 {
				t := time.Now().Add(expires)
				exp = &t
			}
			return withInvites(cmd.Context(), opts, func(ctx context.Context, store *signupgate.Store) error {
				var errs []error
				for _, email := range args {
					inv, err := store.Add(ctx, email, signupgate.AddOptions{Note: note, InvitedBy: invitedBy, ExpiresAt: exp})
					if err != nil {
						errs = append(errs, fmt.Errorf("%s: %w", email, err))
						continue
					}
					cmd.Printf("invited %s\n", inv.Email)
				}
				return errors.Join(errs...)
			})
		},
	}
	add.Flags().StringVar(&note, "note", "", "Free-text context, such as who asked for the invite")
	add.Flags().StringVar(&invitedBy, "invited-by", "", "Label of the operator adding the invite")
	add.Flags().DurationVar(&expires, "expires-in", 0, "Make the invite expire after this long (for example 168h); 0 means never")

	var all bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List pending invites (--all includes redeemed ones)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withInvites(cmd.Context(), opts, func(ctx context.Context, store *signupgate.Store) error {
				invites, err := store.List(ctx, all)
				if err != nil {
					return err
				}
				return writeInvites(cmd.OutOrStdout(), invites, time.Now())
			})
		},
	}
	list.Flags().BoolVar(&all, "all", false, "Include redeemed invites")

	revoke := &cobra.Command{
		Use:   "revoke <email>...",
		Short: "Delete invites, pending or redeemed",
		Long: `Delete the invite for each address. Deleting a redeemed invite does not
touch the account created with it; it only allows the address to be invited
again.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withInvites(cmd.Context(), opts, func(ctx context.Context, store *signupgate.Store) error {
				var errs []error
				for _, email := range args {
					if err := store.Revoke(ctx, email); err != nil {
						errs = append(errs, err)
						continue
					}
					cmd.Printf("revoked %s\n", email)
				}
				return errors.Join(errs...)
			})
		},
	}

	invite.AddCommand(add, list, revoke)
	return invite
}

// withInvites runs fn with the invite store over the configured database.
func withInvites(ctx context.Context, opts *options, fn func(context.Context, *signupgate.Store) error) error {
	return withDatabase(ctx, opts, func(ctx context.Context, client *ent.Client) error {
		return fn(ctx, signupgate.NewStore(client))
	})
}

// withDatabase opens the configured database and runs fn with its client.
// The invite and waitlist tables come from the schema migration
// ("systemauth migrate", or the migration serve runs at startup); these
// commands do not change the schema.
func withDatabase(ctx context.Context, opts *options, fn func(context.Context, *ent.Client) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cfg, err := loadConfig(opts)
	if err != nil {
		return err
	}
	if cfg.Database == nil {
		return errors.New("this command reads the database: set --db-driver and --db-dsn (or a database in the config file)")
	}
	db, err := systemauthsvc.OpenDatabase(cfg.Database)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing database: %w", cerr)
		}
	}()
	return fn(ctx, db.Client)
}

// newWaitlistCmd builds "systemauth waitlist": the addresses that asked to be
// told when sign-up opens, collected by the waitlist page an invite-only
// deployment serves. Nothing is emailed from here; export the list instead.
func newWaitlistCmd(opts *options) *cobra.Command {
	waitlist := &cobra.Command{
		Use:   "waitlist",
		Short: "List, export and remove waitlist entries",
	}
	var asCSV bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List waitlist entries, oldest first (--csv to export)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDatabase(cmd.Context(), opts, func(ctx context.Context, client *ent.Client) error {
				entries, err := signupgate.NewWaitlist(client).List(ctx)
				if err != nil {
					return err
				}
				if asCSV {
					return signupgate.WriteWaitlistCSV(cmd.OutOrStdout(), entries)
				}
				tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
				if _, err := fmt.Fprintln(tw, "EMAIL\tJOINED\tCONSENT"); err != nil {
					return err
				}
				for _, e := range entries {
					if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Email, e.CreatedAt.UTC().Format(time.RFC3339), e.ConsentVersion); err != nil {
						return err
					}
				}
				return tw.Flush()
			})
		},
	}
	list.Flags().BoolVar(&asCSV, "csv", false, "Write CSV (email, joined_at, last_submitted_at, consent_version)")
	remove := &cobra.Command{
		Use:   "remove <email>...",
		Short: "Remove addresses from the waitlist, for example on request",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withDatabase(cmd.Context(), opts, func(ctx context.Context, client *ent.Client) error {
				w := signupgate.NewWaitlist(client)
				var errs []error
				for _, email := range args {
					if err := w.Remove(ctx, email); err != nil {
						errs = append(errs, err)
						continue
					}
					cmd.Printf("removed %s\n", email)
				}
				return errors.Join(errs...)
			})
		},
	}
	waitlist.AddCommand(list, remove)
	return waitlist
}

func writeInvites(w io.Writer, invites []signupgate.Invite, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "EMAIL\tSTATUS\tEXPIRES\tNOTE"); err != nil {
		return err
	}
	for _, inv := range invites {
		expires := "-"
		if inv.ExpiresAt != nil {
			expires = inv.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", inv.Email, inv.Status(now), expires, inv.Note); err != nil {
			return err
		}
	}
	return tw.Flush()
}
