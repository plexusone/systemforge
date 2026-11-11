// Package billingcmd is the "billing" command a SystemAuth host adds to its
// CLI: it syncs the pricing spec's products and prices to the payment
// provider (ADR-021), and shows and sets the plans the operator sets by
// hand (ADR-022).
package billingcmd

import (
	"context"
	"fmt"
	"text/tabwriter"

	payforgestripe "github.com/plexusone/payforge/stripe"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// Load returns the host's SystemAuth configuration, with its secrets
// resolved, and its pricing spec. It runs when a command runs, after flags
// are parsed.
type Load func(ctx context.Context) (*systemauthsvc.Config, *pricingspec.Spec, error)

// Command returns "billing" with its "sync" and "plan" subcommands.
func Command(load Load) *cobra.Command {
	billing := &cobra.Command{
		Use:   "billing",
		Short: "Manage billing at the payment provider",
	}
	var dryRun bool
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Create or update the payment provider's products and prices from the pricing spec",
		Long: `Create or update the payment provider's products and prices from the pricing
spec, so checkout can sell its plans. Run it after changing a plan's price
or name. A price cannot change at the provider, so a changed amount makes a
new price; subscribers stay on the one they bought. With --dry-run it only
reports what it would change.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, spec, err := load(cmd.Context())
			if err != nil {
				return err
			}
			report, err := systemauthsvc.SyncPrices(cmd.Context(), cfg, spec, dryRun)
			if err != nil {
				return err
			}
			return printReport(cmd, report, payforgestripe.KeyMode(cfg.Billing.StripeSecretKey))
		},
	}
	sync.Flags().BoolVar(&dryRun, "dry-run", false, "Report what would change without changing anything")
	billing.AddCommand(sync, planCmd(load))
	return billing
}

func printReport(cmd *cobra.Command, r payforgestripe.SyncReport, mode payforgestripe.Mode) error {
	out := cmd.OutOrStdout()
	tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ACTION\tKEY\tDETAIL"); err != nil {
		return err
	}
	for _, a := range r.Actions {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\n", a.Kind, a.Key, a.Detail); err != nil {
			return err
		}
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	verdict := "in sync"
	switch {
	case r.Changed() && r.DryRun:
		verdict = "changes needed (dry run: nothing changed)"
	case r.Changed():
		verdict = "updated"
	}
	_, err := fmt.Fprintf(out, "%s mode: %s\n", mode, verdict)
	return err
}
