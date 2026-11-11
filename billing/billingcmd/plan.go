package billingcmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/plexusone/systemspec-pricingpackaging/pricingspec"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/billing"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	"github.com/plexusone/systemforge/identity/ent/organization"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

const planLong = `Show, set and clear the plans the deployment's operator sets by hand
(ADR-022): for the organizations that run or test the service, on an
internal plan of the pricing spec, or for one given a plan without paying.

An operator's plan is the organization's plan until it is cleared, whatever
its subscription's status. Billing events never change it, and checkout
refuses to sell the organization a plan while it is set.

An organization is named by its slug, its ID, or the email address of the
person who owns it; the person must have signed in once.`

// env is what a plan command works with. payments is whether the
// deployment takes payments; in free mode a paid subscription grants
// nothing.
type env struct {
	db       *ent.Client
	spec     *pricingspec.Spec
	payments bool
}

// planCmd returns "billing plan".
func planCmd(load Load) *cobra.Command {
	plan := &cobra.Command{
		Use:   "plan",
		Short: "Show, set and clear plans the operator sets by hand",
		Long:  planLong,
	}
	run := func(cmd *cobra.Command, fn func(ctx context.Context, e env) error) (err error) {
		ctx := cmd.Context()
		cfg, spec, err := load(ctx)
		if err != nil {
			return err
		}
		if cfg.Database == nil {
			return errors.New("this command reads the database: configure one")
		}
		conn, err := systemauthsvc.OpenDatabase(cfg.Database)
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, conn.Close()) }()
		return fn(ctx, env{db: conn.Client, spec: spec, payments: cfg.Billing.Configured()})
	}

	plan.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List the organizations on a plan the operator set",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, func(ctx context.Context, e env) error {
				plans, err := billing.OperatorPlans(ctx, e.db)
				if err != nil {
					return err
				}
				return writeOperatorPlans(ctx, cmd.OutOrStdout(), e.db, plans)
			})
		},
	})

	plan.AddCommand(&cobra.Command{
		Use:   "show <organization>",
		Short: "Show an organization's plan and whether the operator set it",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, func(ctx context.Context, e env) error {
				org, err := resolveOrganization(ctx, e.db, args[0])
				if err != nil {
					return err
				}
				return showPlan(ctx, cmd.OutOrStdout(), e, org)
			})
		},
	})

	var note string
	set := &cobra.Command{
		Use:   "set <organization> <plan>",
		Short: "Put an organization on a plan of the pricing spec",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, func(ctx context.Context, e env) error {
				org, err := resolveOrganization(ctx, e.db, args[0])
				if err != nil {
					return err
				}
				err = billing.SetOperatorPlan(ctx, e.db, e.spec, org.ID, args[1], note)
				if errors.Is(err, billing.ErrUnknownPlan) {
					return fmt.Errorf("no plan %q; the plans are %s", args[1], planIDs(e.spec))
				}
				if err != nil {
					return err
				}
				return showPlan(ctx, cmd.OutOrStdout(), e, org)
			})
		},
	}
	set.Flags().StringVar(&note, "note", "", "Why the operator set the plan, kept with it")
	plan.AddCommand(set)

	plan.AddCommand(&cobra.Command{
		Use:   "clear <organization>",
		Short: "Remove the operator's plan, so the organization is on its own again",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, func(ctx context.Context, e env) error {
				org, err := resolveOrganization(ctx, e.db, args[0])
				if err != nil {
					return err
				}
				cleared, err := billing.ClearOperatorPlan(ctx, e.db, org.ID)
				if err != nil {
					return err
				}
				if !cleared {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s has no plan the operator set\n", org.Slug); err != nil {
						return err
					}
				}
				return showPlan(ctx, cmd.OutOrStdout(), e, org)
			})
		},
	})
	return plan
}

// resolveOrganization finds an organization by ID, by slug, or by the email
// address of its owner, who must own exactly one.
func resolveOrganization(ctx context.Context, db *ent.Client, ref string) (*ent.Organization, error) {
	ref = strings.TrimSpace(ref)
	if id, err := uuid.Parse(ref); err == nil {
		o, err := db.Organization.Get(ctx, id)
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("no organization %s", id)
		}
		return o, err
	}
	if !strings.Contains(ref, "@") {
		o, err := db.Organization.Query().Where(organization.SlugEQ(ref)).Only(ctx)
		if ent.IsNotFound(err) {
			return nil, fmt.Errorf("no organization %q", ref)
		}
		return o, err
	}
	h, err := db.Human.Query().Where(human.EmailEqualFold(ref)).Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("%s: no account; the person signs in once first", ref)
	}
	if err != nil {
		return nil, err
	}
	owned, err := db.Organization.Query().Where(organization.OwnerPrincipalID(h.PrincipalID)).
		Order(ent.Asc(organization.FieldSlug)).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(owned) {
	case 0:
		return nil, fmt.Errorf("%s owns no organization", ref)
	case 1:
		return owned[0], nil
	}
	slugs := make([]string, len(owned))
	for i, o := range owned {
		slugs[i] = o.Slug
	}
	return nil, fmt.Errorf("%s owns %d organizations (%s); name one by its slug", ref, len(owned), strings.Join(slugs, ", "))
}

func showPlan(ctx context.Context, w io.Writer, e env, org *ent.Organization) error {
	plan, _, err := billing.OrganizationPlan(ctx, e.db, e.spec, org.ID, e.payments)
	if err != nil {
		return err
	}
	op, set, err := billing.OperatorPlanOf(ctx, e.db, org.ID)
	if err != nil {
		return err
	}
	source := "subscription or default"
	if set {
		source = "operator, " + op.SetAt.UTC().Format(time.DateOnly)
		if op.Note != "" {
			source += ": " + op.Note
		}
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintf(tw, "ORGANIZATION\tPLAN\tSET BY\n%s\t%s\t%s\n", org.Slug, plan.ID, source); err != nil {
		return err
	}
	return tw.Flush()
}

func writeOperatorPlans(ctx context.Context, w io.Writer, db *ent.Client, plans []billing.OperatorPlan) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "ORGANIZATION\tPLAN\tSET\tNOTE"); err != nil {
		return err
	}
	for _, p := range plans {
		slug := p.OrganizationID.String()
		if o, err := db.Organization.Get(ctx, p.OrganizationID); err == nil {
			slug = o.Slug
		} else if !ent.IsNotFound(err) {
			return err
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", slug, p.Plan, p.SetAt.UTC().Format(time.DateOnly), p.Note); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func planIDs(spec *pricingspec.Spec) string {
	ids := make([]string, len(spec.Plans))
	for i, p := range spec.Plans {
		ids[i] = p.ID
	}
	return strings.Join(ids, ", ")
}
