// Package admincmd provides the "admin" cobra command a host CLI mounts to
// grant, revoke and list platform administrators. It opens the identity
// database directly, so the first administrator can be created before any
// exists.
//
// In authorization mode rebac the graph is not written from here: the
// running server's reconciler applies the change at its next run.
package admincmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/principal"
)

// Open opens the identity database for one command, returning its client
// and the function that closes it.
type Open func(ctx context.Context) (client *ent.Client, closeFn func() error, err error)

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

// Command returns "admin" with grant, revoke and list.
func Command(open Open) *cobra.Command {
	admin := &cobra.Command{
		Use:   "admin",
		Short: "Grant, revoke and list platform administrators",
		Long: `Grant, revoke and list platform administrators: people who may manage the
whole deployment, such as its sign-up invites. A person must have an
account, which they get by signing in once.`,
	}
	grant := &cobra.Command{
		Use:   "grant <email>...",
		Short: "Make people platform administrators",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setAdmin(cmd, open, args, true)
		},
	}
	revoke := &cobra.Command{
		Use:   "revoke <email>...",
		Short: "Remove platform administration from people",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return setAdmin(cmd, open, args, false)
		},
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "List platform administrators",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				rows, err := client.Human.Query().Where(human.IsPlatformAdmin(true)).All(ctx)
				if err != nil {
					return fmt.Errorf("listing platform administrators: %w", err)
				}
				return writeAdmins(cmd.OutOrStdout(), rows)
			})
		},
	}
	admin.AddCommand(grant, revoke, list)
	return admin
}

func setAdmin(cmd *cobra.Command, open Open, emails []string, isAdmin bool) error {
	return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
		svc := principal.NewService(client)
		var errs []error
		for _, raw := range emails {
			email := strings.ToLower(strings.TrimSpace(raw))
			h, err := client.Human.Query().Where(human.EmailEQ(email)).Only(ctx)
			if ent.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("%s: no account; the person signs in once first", email))
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", email, err))
				continue
			}
			v := isAdmin
			if _, err := svc.UpdateHuman(ctx, h.PrincipalID, principal.UpdateHumanInput{IsPlatformAdmin: &v}); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", email, err))
				continue
			}
			if isAdmin {
				cmd.Printf("granted %s\n", email)
			} else {
				cmd.Printf("revoked %s\n", email)
			}
		}
		return errors.Join(errs...)
	})
}

func writeAdmins(w io.Writer, rows []*ent.Human) error {
	emails := make([]string, 0, len(rows))
	for _, h := range rows {
		if h.Email != nil {
			emails = append(emails, *h.Email)
		}
	}
	sort.Strings(emails)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "EMAIL"); err != nil {
		return err
	}
	for _, e := range emails {
		if _, err := fmt.Fprintln(tw, e); err != nil {
			return err
		}
	}
	return tw.Flush()
}
