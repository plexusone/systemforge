package signupcmd

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/signupgate"
)

// AllowanceCommand returns "allowance": how many people each member may
// invite with codes of their own.
func AllowanceCommand(open Open) *cobra.Command {
	allowance := &cobra.Command{
		Use:   "allowance",
		Short: "Set and list how many people members may invite",
		Long: `Set and list member invite allowances. A member creates single-use invite
codes up to their allowance; codes already used, and codes still usable,
count against it. A member with no allowance set has the deployment's
default, which is 0 unless the server configures another.`,
	}
	var note string
	set := &cobra.Command{
		Use:   "set <email> <count|default>",
		Short: "Set a member's allowance, or return it to the default",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var granted *int
			if args[1] != "default" {
				n, err := strconv.Atoi(args[1])
				if err != nil || n < 0 {
					return fmt.Errorf("%q is not a count; give a whole number or \"default\"", args[1])
				}
				granted = &n
			}
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				store := signupgate.NewCodeStore(client, signupgate.MemberOptions{})
				id, err := store.PrincipalByEmail(ctx, args[0])
				if err != nil {
					return err
				}
				if err := store.SetAllowance(ctx, id, granted, note, nil); err != nil {
					return err
				}
				cmd.Printf("set %s to %s\n", args[0], args[1])
				return nil
			})
		},
	}
	set.Flags().StringVar(&note, "note", "", "Free-text context for operators")
	list := &cobra.Command{
		Use:   "list",
		Short: "List the allowances operators have set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				list, err := signupgate.NewCodeStore(client, signupgate.MemberOptions{}).Allowances(ctx)
				if err != nil {
					return err
				}
				return writeAllowances(cmd.OutOrStdout(), list)
			})
		},
	}
	allowance.AddCommand(set, list)
	return allowance
}

func writeAllowances(w io.Writer, list []signupgate.Allowance) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "EMAIL\tALLOWANCE\tHELD\tNOTE"); err != nil {
		return err
	}
	for _, a := range list {
		granted := "default"
		if a.Granted != nil {
			granted = strconv.Itoa(*a.Granted)
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", a.Email, granted, a.Held, a.Note); err != nil {
			return err
		}
	}
	return tw.Flush()
}
