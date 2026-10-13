// Package keys wires keyforge into SystemForge (ADR-013): one key library for
// every encryption need on the platform, with the root key read through
// omnivault and lifecycle events sent to the platform audit trail.
//
// This first version runs keyforge's single-host setup: the keyring and its
// registry live together in one directory, so they are backed up together.
package keys

import (
	"context"
	"errors"
	"fmt"

	"github.com/plexusone/keyforge"
	"github.com/plexusone/keyforge/embedded"
	"github.com/plexusone/keyforge/envelope"
	"github.com/plexusone/keyforge/provider/local"

	sfaudit "github.com/plexusone/systemforge/contract/audit"
)

// Options configures [Open].
type Options struct {
	// Dir holds the keyring, the registry and the job state. Required.
	Dir string
	// Root supplies the root key that protects the keyring, for example
	// [VaultSource]. It must not be a file in Dir. Required.
	Root local.RootKeySource
	// Purposes are the purposes to manage. Each gets a key on first start.
	// Required.
	Purposes []keyforge.Purpose
	// Audit receives key lifecycle events. Optional.
	Audit sfaudit.Store
	// AcceptRollback opens a keyring older than one this host has seen, as
	// restoring from backup produces. Set it only after confirming the restore.
	AcceptRollback bool
}

// Keys is a running key system.
type Keys struct {
	sys *embedded.System
}

// Open opens the key system in o.Dir, creating it on first use.
func Open(ctx context.Context, o Options) (*Keys, error) {
	if o.Dir == "" {
		return nil, errors.New("keys: Options.Dir is required")
	}
	if o.Root == nil {
		return nil, errors.New("keys: Options.Root is required")
	}
	if len(o.Purposes) == 0 {
		return nil, errors.New("keys: Options.Purposes is required")
	}
	purposes := make(map[keyforge.Purpose]embedded.PurposeOptions, len(o.Purposes))
	for _, p := range o.Purposes {
		purposes[p] = embedded.PurposeOptions{}
	}
	eo := embedded.Options{
		Dir:            o.Dir,
		Root:           o.Root,
		Purposes:       purposes,
		AcceptRollback: o.AcceptRollback,
	}
	if o.Audit != nil {
		eo.Audit = auditSink{store: o.Audit}
	}
	sys, err := embedded.Open(ctx, eo)
	if err != nil {
		return nil, fmt.Errorf("keys: %w", err)
	}
	return &Keys{sys: sys}, nil
}

// Client returns the keyforge client, for callers that need envelopes.
func (k *Keys) Client() *keyforge.Client { return k.sys.Client }

// Seal encrypts plaintext under purpose, bound to aad, and returns the
// envelope in its binary form.
func (k *Keys) Seal(ctx context.Context, purpose keyforge.Purpose, plaintext, aad []byte) ([]byte, error) {
	e, err := k.sys.Client.Encrypt(ctx, purpose, plaintext, aad)
	if err != nil {
		return nil, err
	}
	return e.MarshalBinary()
}

// Open decrypts a binary envelope produced by [Keys.Seal] with the same
// purpose and aad.
func (k *Keys) Open(ctx context.Context, purpose keyforge.Purpose, sealed, aad []byte) ([]byte, error) {
	e, err := envelope.Parse(sealed)
	if err != nil {
		return nil, err
	}
	pt, _, err := k.sys.Client.Decrypt(ctx, purpose, e, aad)
	return pt, err
}

// Run runs the lifecycle jobs until ctx is cancelled.
func (k *Keys) Run(ctx context.Context) error { return k.sys.Run(ctx) }

// Ready reports whether the key system can serve.
func (k *Keys) Ready(ctx context.Context) error { return k.sys.Ready(ctx) }

// Close releases the key system.
func (k *Keys) Close() error { return k.sys.Close() }
