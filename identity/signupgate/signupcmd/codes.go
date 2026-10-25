package signupcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/signupgate"
)

// CodeCommand returns "code": manage invite codes, which let up to a set
// number of people create an account while the deployment is invite-only.
// signupURL, when not nil, returns the sign-up page URL (for example
// https://auth.example.com/signup); a new code is then also printed as a
// link. It is called after the command's flags are parsed.
func CodeCommand(open Open, signupURL func() string) *cobra.Command {
	code := &cobra.Command{
		Use:   "code",
		Short: "Manage invite codes for an invite-only deployment",
		Long: `Manage invite codes. A code admits up to --max-uses people, whoever holds
it; each still signs in with a verified email. Only a hash of a code is
stored, so a new code is shown once: copy it when it is created. Revoke a
code to stop it admitting anyone else.`,
	}

	var (
		label     string
		note      string
		createdBy string
		maxUses   int
		expires   time.Duration
	)
	create := &cobra.Command{
		Use:   "create",
		Short: "Create an invite code and print it once",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var exp *time.Time
			if expires > 0 {
				t := time.Now().Add(expires)
				exp = &t
			}
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				c, value, err := signupgate.NewCodeStore(client, signupgate.MemberOptions{}).CreateCode(ctx, signupgate.CodeOptions{
					Kind: signupgate.CodeOperator, Label: label, Note: note, CreatedByLabel: createdBy,
					MaxUses: maxUses, ExpiresAt: exp,
				})
				if err != nil {
					return err
				}
				cmd.Printf("code %s (id %s, %d uses)\n", value, c.ID, c.MaxUses)
				if signupURL != nil {
					if base := signupURL(); base != "" {
						cmd.Printf("link %s\n", signupgate.CodeLink(base, value))
					}
				}
				cmd.Println("The code is not stored and cannot be shown again.")
				return nil
			})
		},
	}
	create.Flags().StringVar(&label, "label", "", "Cohort name, such as launch-week")
	create.Flags().StringVar(&note, "note", "", "Free-text context for operators")
	create.Flags().StringVar(&createdBy, "created-by", "", "Label of the operator creating the code")
	create.Flags().IntVar(&maxUses, "max-uses", 1, "How many accounts the code may create")
	create.Flags().DurationVar(&expires, "expires-in", 0, "Make the code expire after this long (for example 336h); 0 means never")

	var (
		all       bool
		listLabel string
	)
	list := &cobra.Command{
		Use:   "list",
		Short: "List usable codes (--all includes used-up, expired and revoked ones)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				codes, err := signupgate.NewCodeStore(client, signupgate.MemberOptions{}).
					ListCodes(ctx, signupgate.CodeFilter{Label: listLabel, ActiveOnly: !all})
				if err != nil {
					return err
				}
				return writeCodes(cmd.OutOrStdout(), codes, time.Now())
			})
		},
	}
	list.Flags().BoolVar(&all, "all", false, "Include used-up, expired and revoked codes")
	list.Flags().StringVar(&listLabel, "label", "", "Only codes with this label")

	revoke := &cobra.Command{
		Use:   "revoke <id>...",
		Short: "Revoke codes so they admit nobody else",
		Long: `Revoke each code by its ID (from "code list"). Accounts already created with
a code are not touched.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				store := signupgate.NewCodeStore(client, signupgate.MemberOptions{})
				var errs []error
				for _, raw := range args {
					id, err := uuid.Parse(raw)
					if err != nil {
						errs = append(errs, fmt.Errorf("%s: not a code ID", raw))
						continue
					}
					if err := store.RevokeCode(ctx, id); err != nil {
						errs = append(errs, fmt.Errorf("%s: %w", raw, err))
						continue
					}
					cmd.Printf("revoked %s\n", id)
				}
				return errors.Join(errs...)
			})
		},
	}

	var joinedLabel string
	joined := &cobra.Command{
		Use:   "joined",
		Short: "List accounts created with codes, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), open, func(ctx context.Context, client *ent.Client) error {
				reds, err := signupgate.NewCodeStore(client, signupgate.MemberOptions{}).
					Redemptions(ctx, signupgate.RedemptionFilter{Label: joinedLabel})
				if err != nil {
					return err
				}
				return writeRedemptions(cmd.OutOrStdout(), reds)
			})
		},
	}
	joined.Flags().StringVar(&joinedLabel, "label", "", "Only accounts created with codes carrying this label")

	code.AddCommand(create, list, revoke, joined)
	return code
}

func writeCodes(w io.Writer, codes []signupgate.Code, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ID\tCODE\tKIND\tLABEL\tUSES\tSTATUS\tEXPIRES"); err != nil {
		return err
	}
	for _, c := range codes {
		expires := "-"
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.UTC().Format(time.RFC3339)
		}
		if _, err := fmt.Fprintf(tw, "%s\t…%s\t%s\t%s\t%d/%d\t%s\t%s\n",
			c.ID, c.Hint, c.Kind, c.Label, c.UseCount, c.MaxUses, c.Status(now), expires); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeRedemptions(w io.Writer, reds []signupgate.Redemption) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "JOINED\tEMAIL\tCODE\tKIND\tLABEL\tCREATED BY"); err != nil {
		return err
	}
	for _, r := range reds {
		by := r.CodeCreatedByLabel
		if r.CodeCreatedBy != nil {
			by = r.CodeCreatedBy.String()
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t…%s\t%s\t%s\t%s\n",
			r.CreatedAt.UTC().Format(time.RFC3339), r.Email, r.CodeHint, r.CodeKind, r.CodeLabel, by); err != nil {
			return err
		}
	}
	return tw.Flush()
}
