// Package secrets resolves secret references in configuration through an
// omnivault vault.
//
// A Resolver expands ${NAME} and $NAME references the way os.ExpandEnv
// does, except that each NAME is read from a vault instead of the process
// environment. The default resolver (Env) is backed by omnivault's
// environment provider and behaves exactly like os.ExpandEnv: a reference
// to a missing secret expands to the empty string.
//
// Any other vault plugs in through New (an omnivault.Vault the deployment
// built itself) or FromURI (an omnivault URI such as env://, file:///dir,
// or a scheme a cloud provider package registered with
// omnivault.RegisterProvider). SystemForge itself imports no cloud SDK: a
// deployment that keeps its secrets in, say, AWS Secrets Manager imports
// that provider's registration package in its own main package.
//
// Errors other than "secret not found" (an unreachable vault, a permission
// error) are returned, never treated as an empty value.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/plexusone/omnivault"
	"github.com/plexusone/omnivault/vault"
)

// Resolver reads secret values from an omnivault vault.
type Resolver struct {
	client *omnivault.Client
}

// Env returns a resolver backed by the process environment, the default:
// Expand then behaves exactly like os.ExpandEnv.
func Env() *Resolver {
	c, err := omnivault.NewClient(omnivault.Config{Provider: omnivault.ProviderEnv})
	if err != nil {
		// The built-in env provider has no configuration that can fail.
		panic(fmt.Sprintf("secrets: env provider: %v", err))
	}
	return &Resolver{client: c}
}

// New returns a resolver backed by v. Close closes v.
func New(v omnivault.Vault) (*Resolver, error) {
	if v == nil {
		return nil, errors.New("secrets: nil vault")
	}
	c, err := omnivault.NewClient(omnivault.Config{CustomVault: v})
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return &Resolver{client: c}, nil
}

// FromURI returns a resolver backed by the vault omnivault.VaultFromURI
// opens for uri (env://, file:///dir, memory://, or a scheme registered
// with omnivault.RegisterProvider). Close closes the vault.
func FromURI(uri string) (*Resolver, error) {
	v, err := omnivault.VaultFromURI(uri)
	if err != nil {
		return nil, fmt.Errorf("secrets: vault %q: %w", uri, err)
	}
	return New(v)
}

// Name returns the backing vault's provider name.
func (r *Resolver) Name() string { return r.client.Name() }

// Close releases the backing vault.
func (r *Resolver) Close() error { return r.client.Close() }

// Lookup returns the secret stored under name and whether it exists. A
// missing secret is not an error; any other vault error is returned.
func (r *Resolver) Lookup(ctx context.Context, name string) (string, bool, error) {
	v, err := r.client.GetValue(ctx, name)
	if err != nil {
		if errors.Is(err, vault.ErrSecretNotFound) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("secrets: %s: %w", name, err)
	}
	return v, true, nil
}

// Expand replaces ${NAME} and $NAME references in s with the secrets they
// name, with os.Expand's syntax; a missing secret expands to the empty
// string. It returns the first vault error.
func (r *Resolver) Expand(ctx context.Context, s string) (string, error) {
	if !strings.Contains(s, "$") {
		return s, nil
	}
	var firstErr error
	out := os.Expand(s, func(name string) string {
		if firstErr != nil {
			return ""
		}
		v, _, err := r.Lookup(ctx, name)
		if err != nil {
			firstErr = err
			return ""
		}
		return v
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// ExpandWhole is Expand for values that may hold arbitrary data, such as
// PEM keys: a value that is entirely one ${NAME} reference (surrounding
// space ignored) is replaced by the secret without re-scanning it, so a
// "$" inside the secret is kept. Anything else goes through Expand.
func (r *Resolver) ExpandWhole(ctx context.Context, s string) (string, error) {
	if name, ok := WholeReference(s); ok {
		v, _, err := r.Lookup(ctx, name)
		return v, err
	}
	return r.Expand(ctx, s)
}

// WholeReference reports whether s is entirely one ${NAME} reference and
// returns NAME.
func WholeReference(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "${") && strings.HasSuffix(t, "}") && !strings.ContainsAny(t[2:len(t)-1], "${} ") {
		return t[2 : len(t)-1], true
	}
	return "", false
}
