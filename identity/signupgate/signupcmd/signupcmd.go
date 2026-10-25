// Package signupcmd provides the operator commands for invite-only sign-up
// as cobra commands a host CLI mounts: "invite" (add, list, revoke), "code"
// (create, list, revoke, joined) and "waitlist" (list, invite, remove). They open the identity database directly, so
// they work whether or not the server is running, and never change the
// schema; the tables come from the schema migration.
package signupcmd

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
)

// Open opens the identity database for one command, returning its client
// and the function that closes it.
type Open func(ctx context.Context) (client *ent.Client, closeFn func() error, err error)

// run opens the database, runs fn and closes it, reporting a close failure
// when fn succeeded.
func run(ctx context.Context, open Open, fn func(context.Context, *ent.Client) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client, closeFn, err := open(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeFn(); cerr != nil && err == nil {
			err = fmt.Errorf("closing database: %w", cerr)
		}
	}()
	return fn(ctx, client)
}

// InviteCommand returns "invite": manage the addresses allowed to create an
// account while the deployment is invite-only.
func InviteCommand(open Open) *cobra.Command {
	invite := &cobra.Command{
		Use:   "invite",
		Short: "Manage sign-up invites for an invite-only deployment",
		Long: `Manage the email addresses allowed to create an account while the
deployment is invite-only. An invite is an address, not a code: the person
signs in with the upstream provider, and the account is created when that
provider's verified email matches an invite. People who already have an
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
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				store := signupgate.NewStore(client)
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
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				invites, err := signupgate.NewStore(client).List(ctx, all)
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
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				store := signupgate.NewStore(client)
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

// WaitlistCommand returns "waitlist": the addresses that asked to be told
// when sign-up opens. Nothing is emailed from here; export the list instead.
func WaitlistCommand(open Open) *cobra.Command {
	waitlist := &cobra.Command{
		Use:   "waitlist",
		Short: "List, export, invite and remove waitlist entries",
	}
	var asCSV bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List waitlist entries, oldest first (--csv to export)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				entries, err := signupgate.NewWaitlist(client).List(ctx)
				if err != nil {
					return err
				}
				if asCSV {
					return signupgate.WriteWaitlistCSV(cmd.OutOrStdout(), entries)
				}
				return writeWaitlist(cmd.OutOrStdout(), entries)
			})
		},
	}
	list.Flags().BoolVar(&asCSV, "csv", false, "Write CSV (email, joined_at, last_submitted_at, consent_version)")
	remove := &cobra.Command{
		Use:   "remove <email>...",
		Short: "Remove addresses from the waitlist, for example on request",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
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
	var (
		inviteAll  bool
		inviteNote string
		inviteBy   string
		inviteExp  time.Duration
	)
	invite := &cobra.Command{
		Use:   "invite [<email>...]",
		Short: "Invite waitlisted addresses (--all for every one not yet invited)",
		Long: `Create an email invite for each address and mark its waitlist entry
invited. Entries stay on the waitlist. With --all, every entry not yet
invited is invited.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if inviteAll == (len(args) > 0) {
				return errors.New("name addresses or pass --all, not both")
			}
			var exp *time.Time
			if inviteExp > 0 {
				t := time.Now().Add(inviteExp)
				exp = &t
			}
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				w := signupgate.NewWaitlist(client)
				emails := args
				if inviteAll {
					entries, err := w.List(ctx)
					if err != nil {
						return err
					}
					for _, e := range entries {
						if e.InvitedAt == nil {
							emails = append(emails, e.Email)
						}
					}
				}
				invited, err := w.Invite(ctx, signupgate.NewStore(client), emails,
					signupgate.AddOptions{Note: inviteNote, InvitedBy: inviteBy, ExpiresAt: exp})
				for _, inv := range invited {
					cmd.Printf("invited %s\n", inv.Email)
				}
				return err
			})
		},
	}
	invite.Flags().BoolVar(&inviteAll, "all", false, "Invite every entry not yet invited")
	invite.Flags().StringVar(&inviteNote, "note", "", "Free-text context for the invites")
	invite.Flags().StringVar(&inviteBy, "invited-by", "", "Label of the operator adding the invites")
	invite.Flags().DurationVar(&inviteExp, "expires-in", 0, "Make the invites expire after this long; 0 means never")

	waitlist.AddCommand(list, invite, remove)
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

func writeWaitlist(w io.Writer, entries []signupgate.WaitlistEntry) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "EMAIL\tJOINED\tCONSENT"); err != nil {
		return err
	}
	for _, e := range entries {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Email, e.CreatedAt.UTC().Format(time.RFC3339), e.ConsentVersion); err != nil {
			return err
		}
	}
	return tw.Flush()
}
