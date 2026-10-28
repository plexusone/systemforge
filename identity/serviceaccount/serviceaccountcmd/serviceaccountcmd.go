// Package serviceaccountcmd provides the "service-account" cobra command a
// host CLI mounts to manage service accounts: create, list, show, disable,
// enable and delete accounts; add, list and revoke their keys; and grant and
// remove their application roles. It opens the identity database directly,
// so it works whether or not the server is running, and never changes the
// schema.
//
// Access changes the commands make (disabling an account, removing a role,
// revoking the last key) are recorded in the database, where applications
// read them; announcing them to a running server's in-process sinks is the
// server's job.
package serviceaccountcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/plexusone/systemforge/authz"
	"github.com/plexusone/systemforge/identity/approle"
	"github.com/plexusone/systemforge/identity/ent"
	"github.com/plexusone/systemforge/identity/ent/organization"
	entprincipal "github.com/plexusone/systemforge/identity/ent/principal"
	"github.com/plexusone/systemforge/identity/principal"
	"github.com/plexusone/systemforge/identity/serviceaccount"
)

// Open opens the identity database for one command, returning its client
// and the function that closes it.
type Open func(ctx context.Context) (client *ent.Client, closeFn func() error, err error)

// Options configure the command.
type Options struct {
	// Service builds the service-account service over an open client.
	// Default: DefaultService(nil), which cannot grant or remove roles.
	Service func(client *ent.Client) (*serviceaccount.Service, error)
	// Issuer returns SystemAuth's issuer URL, printed with a new key so the
	// workload has everything it needs. Nil leaves it out.
	Issuer func() string
}

// DefaultService builds the service with the host's application role
// vocabularies, so role commands accept the host's applications. With a nil
// registry no application is known: roles cannot be granted, but accounts
// can still be deleted with any roles they hold.
func DefaultService(registry *authz.VocabularyRegistry, opts ...approle.Option) func(*ent.Client) (*serviceaccount.Service, error) {
	if registry == nil {
		registry = authz.NewVocabularyRegistry()
	}
	return func(client *ent.Client) (*serviceaccount.Service, error) {
		return serviceaccount.New(serviceaccount.Config{
			Client:     client,
			Principals: principal.NewService(client),
			Roles:      approle.NewService(client, registry, opts...),
		})
	}
}

type runner struct {
	open Open
	opts Options
	json bool
}

// env is an open database and the service over it.
type env struct {
	client *ent.Client
	svc    *serviceaccount.Service
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
	build := r.opts.Service
	if build == nil {
		build = DefaultService(nil)
	}
	svc, err := build(client)
	if err != nil {
		return err
	}
	return fn(ctx, env{client: client, svc: svc})
}

// Command returns "service-account" and its subcommands.
func Command(open Open, opts Options) *cobra.Command {
	r := &runner{open: open, opts: opts}
	cmd := &cobra.Command{
		Use:     "service-account",
		Aliases: []string{"service-accounts"},
		Short:   "Manage service accounts: automation that calls APIs with a key pair",
		Long: `Manage service accounts. A service account belongs to one organization,
holds application roles there like a member, and authenticates with a
private key it never shares: it signs a short assertion, and SystemAuth
issues it a short-lived DPoP-bound token (the JWT-bearer grant, which the
deployment enables with oauth.jwt_bearer.enabled). SystemAuth stores only
public keys.

An account is named by its ID or its identifier (sa_...).`,
	}
	cmd.PersistentFlags().BoolVar(&r.json, "json", false, "Write JSON")
	cmd.AddCommand(r.createCmd(), r.listCmd(), r.showCmd(),
		r.stateCmd("disable", "Disable an account; its tokens stop working", (*serviceaccount.Service).Disable),
		r.stateCmd("enable", "Enable a disabled account", (*serviceaccount.Service).Enable),
		r.stateCmd("delete", "Delete an account, its keys, roles and membership", (*serviceaccount.Service).Delete),
		r.keyCmd(), r.roleCmd())
	return cmd
}

func (r *runner) createCmd() *cobra.Command {
	var org, name, description, by string
	var scopes []string
	c := &cobra.Command{
		Use:   "create",
		Short: "Create a service account in an organization",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				orgID, err := orgBySlug(ctx, e.client, org)
				if err != nil {
					return err
				}
				byID, err := parseBy(by)
				if err != nil {
					return err
				}
				acct, err := e.svc.Create(ctx, serviceaccount.CreateInput{
					OrganizationID: orgID, Name: name, Description: description, Scopes: scopes, CreatedBy: byID,
				})
				if err != nil {
					return err
				}
				if r.json {
					return writeJSON(cmd.OutOrStdout(), acct)
				}
				cmd.Printf("created %s (%s) in %s\n", acct.Identifier, acct.ID, org)
				return nil
			})
		},
	}
	c.Flags().StringVar(&org, "org", "", "Organization slug (required)")
	c.Flags().StringVar(&name, "name", "", "Account name, such as ci-publisher (required)")
	c.Flags().StringVar(&description, "description", "", "What the account is for")
	c.Flags().StringSliceVar(&scopes, "scope", nil, "Scopes the account may be granted (repeatable)")
	c.Flags().StringVar(&by, "by", "", "The operator's principal ID, recorded as the creator")
	mustRequire(c, "org", "name")
	return c
}

func (r *runner) listCmd() *cobra.Command {
	var org string
	c := &cobra.Command{
		Use:   "list",
		Short: "List an organization's service accounts",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				orgID, err := orgBySlug(ctx, e.client, org)
				if err != nil {
					return err
				}
				accts, err := e.svc.List(ctx, orgID)
				if err != nil {
					return err
				}
				if r.json {
					return writeJSON(cmd.OutOrStdout(), accts)
				}
				return writeAccounts(cmd.OutOrStdout(), accts)
			})
		},
	}
	c.Flags().StringVar(&org, "org", "", "Organization slug (required)")
	mustRequire(c, "org")
	return c
}

func (r *runner) showCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <account>",
		Short: "Show a service account and its keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				acct, err := e.svc.Get(ctx, id)
				if err != nil {
					return err
				}
				keys, err := e.svc.ListKeys(ctx, id)
				if err != nil {
					return err
				}
				if r.json {
					return writeJSON(cmd.OutOrStdout(), map[string]any{"account": acct, "keys": keys})
				}
				if err := writeAccounts(cmd.OutOrStdout(), []*serviceaccount.Account{acct}); err != nil {
					return err
				}
				cmd.Println()
				return writeKeys(cmd.OutOrStdout(), keys)
			})
		},
	}
}

func (r *runner) stateCmd(use, short string, fn func(*serviceaccount.Service, context.Context, uuid.UUID, uuid.UUID) error) *cobra.Command {
	var by string
	c := &cobra.Command{
		Use:   use + " <account>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				byID, err := parseBy(by)
				if err != nil {
					return err
				}
				if err := fn(e.svc, ctx, id, byID); err != nil {
					return err
				}
				cmd.Printf("%sd %s\n", use, args[0])
				return nil
			})
		},
	}
	c.Flags().StringVar(&by, "by", "", "The operator's principal ID, recorded with the change")
	return c
}

func (r *runner) keyCmd() *cobra.Command {
	key := &cobra.Command{Use: "key", Short: "Add, list and revoke a service account's keys"}
	key.AddCommand(r.keyAddCmd(), r.keyListCmd(), r.keyRevokeCmd())
	return key
}

func (r *runner) keyAddCmd() *cobra.Command {
	var out, publicKey, name string
	var scopes []string
	var expires time.Duration
	c := &cobra.Command{
		Use:   "add <account>",
		Short: "Add a key: generate one into --out, or register --public-key",
		Long: `Add a key to a service account. With --out, a P-256 key pair is generated:
the private key is written to that file, readable only by its owner, and
never stored. With --public-key, the public key in that PEM file is
registered (ES256, RS256 with 2048 bits or more, or EdDSA).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if (out == "") == (publicKey == "") {
				return errors.New("set exactly one of --out and --public-key")
			}
			in := serviceaccount.KeyInput{Name: name, Scopes: scopes}
			if expires > 0 {
				t := time.Now().Add(expires)
				in.ExpiresAt = &t
			}
			if publicKey != "" {
				b, err := os.ReadFile(publicKey) //nolint:gosec // G304: the operator names the file
				if err != nil {
					return err
				}
				in.PublicKeyPEM = string(b)
			}
			if out != "" {
				// Fail before touching the database when the file exists.
				if _, err := os.Stat(out); err == nil {
					return fmt.Errorf("%s exists; choose another file", out)
				} else if !errors.Is(err, os.ErrNotExist) {
					return err
				}
			}
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				acct, err := e.svc.Get(ctx, id)
				if err != nil {
					return err
				}
				k, err := e.svc.AddKey(ctx, id, in)
				if err != nil {
					return err
				}
				if out != "" {
					if err := writePrivateKey(out, k.PrivateKeyPEM); err != nil {
						return fmt.Errorf("the key %s was added but its private key was not saved, so revoke it: %w", k.KeyID, err)
					}
				}
				return r.printKey(cmd, acct, k, out)
			})
		},
	}
	c.Flags().StringVar(&out, "out", "", "Generate a key pair and write the private key to this new file")
	c.Flags().StringVar(&publicKey, "public-key", "", "Register the public key in this PEM file")
	c.Flags().StringVar(&name, "name", "", "A label for the key")
	c.Flags().StringSliceVar(&scopes, "scope", nil, "Limit the key to these scopes (repeatable); default: the account's")
	c.Flags().DurationVar(&expires, "expires-in", 0, "Make the key expire after this long (for example 2160h); 0 means never")
	return c
}

func (r *runner) printKey(cmd *cobra.Command, acct *serviceaccount.Account, k *serviceaccount.Key, out string) error {
	issuer := ""
	if r.opts.Issuer != nil {
		issuer = r.opts.Issuer()
	}
	if r.json {
		return writeJSON(cmd.OutOrStdout(), map[string]any{
			"account": acct.Identifier, "key_id": k.KeyID, "algorithm": k.Algorithm,
			"issuer": issuer, "private_key_file": out,
		})
	}
	cmd.Printf("added key %s (%s) to %s\n", k.KeyID, k.Algorithm, acct.Identifier)
	if out != "" {
		cmd.Printf("private key: %s (keep it secret; it is not stored anywhere else)\n", out)
	}
	cmd.Println("\nThe workload needs:")
	if issuer != "" {
		cmd.Printf("  issuer:  %s\n", issuer)
	}
	cmd.Printf("  account: %s\n  key ID:  %s\n", acct.Identifier, k.KeyID)
	return nil
}

// writePrivateKey creates path with owner-only permissions, refusing to
// overwrite a file.
func writePrivateKey(path, pemKey string) (err error) {
	if pemKey == "" {
		return errors.New("no private key was generated")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the operator names the file
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.WriteString(pemKey)
	return err
}

func (r *runner) keyListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list <account>",
		Short: "List a service account's keys",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				keys, err := e.svc.ListKeys(ctx, id)
				if err != nil {
					return err
				}
				if r.json {
					return writeJSON(cmd.OutOrStdout(), keys)
				}
				return writeKeys(cmd.OutOrStdout(), keys)
			})
		},
	}
}

func (r *runner) keyRevokeCmd() *cobra.Command {
	var reason string
	c := &cobra.Command{
		Use:   "revoke <account> <key-id>",
		Short: "Revoke a key; revoking the last one also ends the account's tokens",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				if err := e.svc.RevokeKey(ctx, id, args[1], reason); err != nil {
					return err
				}
				cmd.Printf("revoked key %s\n", args[1])
				return nil
			})
		},
	}
	c.Flags().StringVar(&reason, "reason", "", "Why the key is revoked")
	return c
}

func (r *runner) roleCmd() *cobra.Command {
	role := &cobra.Command{Use: "role", Short: "Grant and remove a service account's application roles"}
	var app, name, by string
	grant := &cobra.Command{
		Use:   "grant <account>",
		Short: "Grant an application role in the account's organization",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				byID, err := parseBy(by)
				if err != nil {
					return err
				}
				if err := e.svc.GrantRole(ctx, id, app, name, byID); err != nil {
					return err
				}
				cmd.Printf("granted %s %s to %s\n", app, name, args[0])
				return nil
			})
		},
	}
	grant.Flags().StringVar(&app, "app", "", "Application (required)")
	grant.Flags().StringVar(&name, "role", "", "Role in the application (required)")
	grant.Flags().StringVar(&by, "by", "", "The operator's principal ID, recorded as the assigner")
	mustRequire(grant, "app", "role")

	var removeApp, removeBy string
	remove := &cobra.Command{
		Use:   "remove <account>",
		Short: "Remove the account's role in an application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return r.run(cmd.Context(), func(ctx context.Context, e env) error {
				id, err := accountID(ctx, e.client, args[0])
				if err != nil {
					return err
				}
				byID, err := parseBy(removeBy)
				if err != nil {
					return err
				}
				if err := e.svc.RemoveRole(ctx, id, removeApp, byID); err != nil {
					return err
				}
				cmd.Printf("removed %s role from %s\n", removeApp, args[0])
				return nil
			})
		},
	}
	remove.Flags().StringVar(&removeApp, "app", "", "Application (required)")
	remove.Flags().StringVar(&removeBy, "by", "", "The operator's principal ID, recorded with the change")
	mustRequire(remove, "app")
	role.AddCommand(grant, remove)
	return role
}

func mustRequire(c *cobra.Command, flags ...string) {
	for _, f := range flags {
		if err := c.MarkFlagRequired(f); err != nil {
			panic(err) // a programming error: the flag is declared above
		}
	}
}

func orgBySlug(ctx context.Context, client *ent.Client, slug string) (uuid.UUID, error) {
	o, err := client.Organization.Query().Where(organization.Slug(slug)).Only(ctx)
	if ent.IsNotFound(err) {
		return uuid.Nil, fmt.Errorf("no organization with slug %q", slug)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return o.ID, nil
}

// accountID resolves an account ID or identifier.
func accountID(ctx context.Context, client *ent.Client, ref string) (uuid.UUID, error) {
	if id, err := uuid.Parse(ref); err == nil {
		return id, nil
	}
	p, err := client.Principal.Query().
		Where(entprincipal.Identifier(ref), entprincipal.TypeEQ(entprincipal.TypeService)).
		Only(ctx)
	if ent.IsNotFound(err) {
		return uuid.Nil, fmt.Errorf("%w: %s", serviceaccount.ErrNotFound, ref)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return p.ID, nil
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

func writeAccounts(w io.Writer, accts []*serviceaccount.Account) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "IDENTIFIER\tNAME\tACTIVE\tSCOPES\tLAST USED\tID"); err != nil {
		return err
	}
	for _, a := range accts {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%t\t%s\t%s\t%s\n", a.Identifier, a.Name, a.Active,
			strings.Join(a.AllowedScopes, ","), when(a.LastUsedAt), a.ID); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func writeKeys(w io.Writer, keys []*serviceaccount.Key) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "KEY ID\tALGORITHM\tNAME\tSTATE\tEXPIRES\tLAST USED"); err != nil {
		return err
	}
	now := time.Now()
	for _, k := range keys {
		state := "usable"
		switch {
		case k.Revoked:
			state = "revoked"
		case !k.Usable(now):
			state = "unusable"
		}
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", k.KeyID, k.Algorithm, k.Name, state,
			when(k.ExpiresAt), when(k.LastUsedAt)); err != nil {
			return err
		}
	}
	return tw.Flush()
}

func when(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}
