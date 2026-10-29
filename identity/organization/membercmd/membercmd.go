// Package membercmd provides the "org" cobra command a host CLI mounts so
// an operator can add, remove and list an organization's members and their
// application roles. It opens the identity database directly and applies
// the changes through organization.Service and approle.Service, exactly as
// the HTTP API does, but without an authorization check: it is for
// recovery and bootstrap, such as restoring an owner who lost access or
// granting the first role in a product before the product can grant one
// itself.
//
// Access the commands remove (a membership, an application role) is
// recorded in the database as access changes, where applications read
// them. In authorization mode rebac the graph is not written from here:
// the running server's reconciler applies the change at its next run.
package membercmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/human"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/organization"
)

// Open opens the identity database for one command, returning its client
// and the function that closes it.
type Open func(ctx context.Context) (client *ent.Client, closeFn func() error, err error)

// Options configure the command.
type Options struct {
	// Roles builds the application-role service over an open client.
	// Default: DefaultRoles(nil), which knows no application, so roles
	// cannot be granted (memberships can still be managed, and removing a
	// member still removes the roles it holds).
	Roles func(client *ent.Client) *approle.Service
}

// DefaultRoles builds the application-role service with the host's role
// vocabularies and entitlement options (for example
// marketplace.ApproleOptions or approle.EntitleAll), so --role accepts the
// host's applications. A nil registry knows no application.
func DefaultRoles(registry *authz.VocabularyRegistry, opts ...approle.Option) func(*ent.Client) *approle.Service {
	if registry == nil {
		registry = authz.NewVocabularyRegistry()
	}
	return func(client *ent.Client) *approle.Service {
		return approle.NewService(client, registry, opts...)
	}
}

// membershipRoles are the organization roles an operator may give.
var membershipRoles = []string{organization.RoleOwner, organization.RoleAdmin, organization.RoleMember, "collaborator"}

type runner struct {
	open Open
	opts Options
	json bool
}

// env is an open database and the services over it.
type env struct {
	client *ent.Client
	orgs   organization.Service
	roles  *approle.Service
}

func (r *runner) run(ctx context.Context, fn func(context.Context, env) error) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	client, closeFn, err := r.open(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeFn(); cerr != nil && err == nil {
			err = fmt.Errorf("closing database: %w", cerr)
		}
	}()
	build := r.opts.Roles
	if build == nil {
		build = DefaultRoles(nil)
	}
	return fn(ctx, env{client: client, orgs: organization.NewService(client), roles: build(client)})
}

// Command returns "org" with "member add|remove|list".
func Command(open Open, opts Options) *cobra.Command {
	r := &runner{open: open, opts: opts}
	org := &cobra.Command{
		Use:     "org",
		Aliases: []string{"organization"},
		Short:   "Operator commands for organizations",
	}
	member := &cobra.Command{
		Use:     "member",
		Aliases: []string{"members"},
		Short:   "Add, remove and list an organization's members and their application roles",
		Long: `Add, remove and list an organization's members and their application roles,
without the authorization checks of the HTTP API: for recovery and
bootstrap. An organization is named by its slug (a slug it gave up within
the cooling-off period also works); a person by their email or principal
ID. A person must have an account, which they get by signing in once.

Application roles are written app:role, e.g. --role billing:admin.`,
	}
	member.PersistentFlags().BoolVar(&r.json, "json", false, "Write JSON")
	member.AddCommand(r.addCmd(), r.removeCmd(), r.listCmd())
	org.AddCommand(member)
	return org
}

func (r *runner) addCmd() *cobra.Command {
	var orgRole, by string
	var appRoles []string
	c := &cobra.Command{
		Use:   "add <org> <person>",
		Short: "Add a member, or give an existing member a role or application roles",
		Long: `Add a person to an organization with --org-role (default member). If they
are already a member, their organization role changes only when
--org-role is given. Each --role app:role is assigned, or changed when
they already hold a role in that application.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsed, err := parseAppRoles(appRoles)
			if err != nil {
				return err
			}
			if !slices.Contains(membershipRoles, orgRole) {
				return fmt.Errorf("--org-role must be one of %s", strings.Join(membershipRoles, ", "))
			}
			byID, err := parseBy(by)
			if err != nil {
				return err
			}
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				org, err := resolveOrg(ctx, e.orgs, args[0])
				if err != nil {
					return err
				}
				pid, err := resolvePerson(ctx, e.client, args[1])
				if err != nil {
					return err
				}
				if err := addMembership(ctx, cmd, e, org, pid, label(args[1]), orgRole, cmd.Flags().Changed("org-role")); err != nil {
					return err
				}
				for _, ar := range parsed {
					if err := setAppRole(ctx, e.roles, approle.AssignInput{
						OrganizationID: org.ID, PrincipalID: pid,
						Application: ar.app, Role: ar.role, AssignedBy: byID,
					}); err != nil {
						return fmt.Errorf("%s:%s: %w", ar.app, ar.role, err)
					}
					cmd.Printf("granted %s:%s to %s in %s\n", ar.app, ar.role, label(args[1]), org.Slug)
				}
				return nil
			})
		},
	}
	c.Flags().StringVar(&orgRole, "org-role", organization.RoleMember, "Organization role: "+strings.Join(membershipRoles, ", "))
	c.Flags().StringArrayVar(&appRoles, "role", nil, "Application role as app:role (repeatable)")
	c.Flags().StringVar(&by, "by", "", "The operator's principal ID, recorded as the assigner")
	return c
}

// addMembership adds pid to org with role, or, when pid is already a
// member and the role was given explicitly, changes its role.
func addMembership(ctx context.Context, cmd *cobra.Command, e env, org *organization.Organization, pid uuid.UUID, who, role string, explicit bool) error {
	existing, err := e.orgs.GetMembership(ctx, org.ID, pid)
	switch {
	case errors.Is(err, organization.ErrMembershipNotFound):
		if _, err := e.orgs.AddMember(ctx, organization.AddMemberInput{
			OrganizationID: org.ID, PrincipalID: pid, Role: role,
		}); err != nil {
			return err
		}
		cmd.Printf("added %s to %s as %s\n", who, org.Slug, role)
		return nil
	case err != nil:
		return err
	}
	if !explicit || (existing.Role == role && existing.Active) {
		cmd.Printf("%s is already %s of %s\n", who, existing.Role, org.Slug)
		return nil
	}
	active := true
	if _, err := e.orgs.UpdateMember(ctx, existing.ID, organization.UpdateMemberInput{Role: &role, Active: &active}); err != nil {
		return err
	}
	cmd.Printf("changed %s in %s from %s to %s\n", who, org.Slug, existing.Role, role)
	return nil
}

// setAppRole assigns the role, or changes the one the principal holds in
// the application, like the HTTP API's PUT.
func setAppRole(ctx context.Context, roles *approle.Service, in approle.AssignInput) error {
	_, err := roles.Change(ctx, in)
	if errors.Is(err, approle.ErrNotAssigned) {
		_, err = roles.Assign(ctx, in)
	}
	return err
}

func (r *runner) removeCmd() *cobra.Command {
	var apps []string
	var by string
	c := &cobra.Command{
		Use:   "remove <org> <person>",
		Short: "Remove a member, or only their roles in the --app applications",
		Long: `Remove a person from an organization, with their application roles, resource
grants and pending invitations. With --app, remove only their roles in
those applications and keep the membership.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			byID, err := parseBy(by)
			if err != nil {
				return err
			}
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				org, err := resolveOrg(ctx, e.orgs, args[0])
				if err != nil {
					return err
				}
				pid, err := resolvePerson(ctx, e.client, args[1])
				if err != nil {
					return err
				}
				if len(apps) == 0 {
					if err := e.orgs.RemoveMember(ctx, org.ID, pid); err != nil {
						return err
					}
					cmd.Printf("removed %s from %s\n", label(args[1]), org.Slug)
					return nil
				}
				var errs []error
				for _, app := range apps {
					if err := e.roles.Remove(ctx, org.ID, pid, app, byID); err != nil {
						errs = append(errs, fmt.Errorf("%s: %w", app, err))
						continue
					}
					cmd.Printf("removed %s role from %s in %s\n", app, label(args[1]), org.Slug)
				}
				return errors.Join(errs...)
			})
		},
	}
	c.Flags().StringArrayVar(&apps, "app", nil, "Remove only the role in this application (repeatable)")
	c.Flags().StringVar(&by, "by", "", "The operator's principal ID, recorded with the change")
	return c
}

// Member is one row of "member list".
type Member struct {
	PrincipalID string            `json:"principal_id"`
	Email       string            `json:"email,omitempty"`
	Role        string            `json:"role"`
	Active      bool              `json:"active"`
	AppRoles    map[string]string `json:"app_roles,omitempty"`
}

func (r *runner) listCmd() *cobra.Command {
	var inactive bool
	c := &cobra.Command{
		Use:   "list <org>",
		Short: "List an organization's members with their stored application roles",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				org, err := resolveOrg(ctx, e.orgs, args[0])
				if err != nil {
					return err
				}
				members, err := listMembers(ctx, e, org.ID, inactive)
				if err != nil {
					return err
				}
				if r.json {
					return writeJSON(cmd.OutOrStdout(), members)
				}
				return writeMembers(cmd.OutOrStdout(), members)
			})
		},
	}
	c.Flags().BoolVar(&inactive, "include-inactive", false, "Also list deactivated memberships")
	return c
}

func listMembers(ctx context.Context, e env, orgID uuid.UUID, inactive bool) ([]Member, error) {
	var opts []organization.ListOption
	if inactive {
		opts = append(opts, organization.IncludeInactive())
	}
	ms, err := e.orgs.ListMembers(ctx, orgID, opts...)
	if err != nil {
		return nil, err
	}
	roles, err := e.roles.ListForOrganization(ctx, orgID, "")
	if err != nil {
		return nil, err
	}
	byPrincipal := map[uuid.UUID]map[string]string{}
	for _, ar := range roles {
		if byPrincipal[ar.PrincipalID] == nil {
			byPrincipal[ar.PrincipalID] = map[string]string{}
		}
		byPrincipal[ar.PrincipalID][ar.Application] = ar.Role
	}
	ids := make([]uuid.UUID, len(ms))
	for i, m := range ms {
		ids[i] = m.PrincipalID
	}
	humans, err := e.client.Human.Query().Where(human.PrincipalIDIn(ids...)).All(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading member emails: %w", err)
	}
	emails := map[uuid.UUID]string{}
	for _, h := range humans {
		if h.Email != nil {
			emails[h.PrincipalID] = *h.Email
		}
	}
	out := make([]Member, len(ms))
	for i, m := range ms {
		out[i] = Member{
			PrincipalID: m.PrincipalID.String(), Email: emails[m.PrincipalID],
			Role: m.Role, Active: m.Active, AppRoles: byPrincipal[m.PrincipalID],
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Email != out[j].Email {
			return out[i].Email < out[j].Email
		}
		return out[i].PrincipalID < out[j].PrincipalID
	})
	return out, nil
}

func writeMembers(w io.Writer, members []Member) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "EMAIL\tROLE\tACTIVE\tAPP ROLES\tPRINCIPAL ID"); err != nil {
		return err
	}
	for _, m := range members {
		apps := make([]string, 0, len(m.AppRoles))
		for app, role := range m.AppRoles {
			apps = append(apps, app+":"+role)
		}
		sort.Strings(apps)
		email, appList := m.Email, strings.Join(apps, ",")
		if email == "" {
			email = "-"
		}
		if appList == "" {
			appList = "-"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\n", email, m.Role, m.Active, appList, m.PrincipalID); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func resolveOrg(ctx context.Context, orgs organization.Service, slug string) (*organization.Organization, error) {
	org, _, err := orgs.ResolveSlug(ctx, slug)
	if err != nil {
		return nil, err
	}
	return org, nil
}

// label is how a person reference is printed: a normalized email, or the
// principal ID as given.
func label(ref string) string {
	if _, err := uuid.Parse(ref); err == nil {
		return ref
	}
	return strings.ToLower(strings.TrimSpace(ref))
}

// resolvePerson resolves an email or principal ID to a principal ID.
func resolvePerson(ctx context.Context, client *ent.Client, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		exists, err := client.Principal.Query().Where(entprincipal.ID(id)).Exist(ctx)
		if err != nil {
			return uuid.Nil, err
		}
		if !exists {
			return uuid.Nil, fmt.Errorf("no principal %s", id)
		}
		return id, nil
	}
	email := strings.ToLower(strings.TrimSpace(ref))
	h, err := client.Human.Query().Where(human.EmailEQ(email)).Only(ctx)
	if ent.IsNotFound(err) {
		return uuid.Nil, fmt.Errorf("%s: no account; the person signs in once first", email)
	}
	if err != nil {
		return uuid.Nil, fmt.Errorf("%s: %w", email, err)
	}
	return h.PrincipalID, nil
}

type appRole struct{ app, role string }

func parseAppRoles(raw []string) ([]appRole, error) {
	out := make([]appRole, 0, len(raw))
	seen := map[string]bool{}
	for _, s := range raw {
		app, role, ok := strings.Cut(s, ":")
		app, role = strings.TrimSpace(app), strings.TrimSpace(role)
		if !ok || app == "" || role == "" {
			return nil, fmt.Errorf("--role %q: want app:role", s)
		}
		if seen[app] {
			return nil, fmt.Errorf("--role: %s given twice", app)
		}
		seen[app] = true
		out = append(out, appRole{app: app, role: role})
	}
	return out, nil
}

func parseBy(by string) (uuid.UUID, error) {
	if by == "" {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(by)
	if err != nil {
		return uuid.Nil, fmt.Errorf("--by must be a principal ID: %w", err)
	}
	return id, nil
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
