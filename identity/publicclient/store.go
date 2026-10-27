package publicclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// ErrNotLoggedIn means the store holds no credentials: the person has not
// logged in, or has logged out.
var ErrNotLoggedIn = errors.New("publicclient: not logged in")

// Credentials are what a public client keeps between runs: the DPoP key
// its tokens are bound to, and the tokens. The key is as sensitive as the
// refresh token: together they act for the person until the refresh token
// is revoked.
type Credentials struct {
	// Issuer and ClientID name the SystemAuth deployment and the client
	// the tokens were issued by and to.
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	// DPoPKey is the serialized key pair (dpop.KeyPair.SerializeJSON).
	DPoPKey json.RawMessage `json:"dpop_key"`

	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`

	// Subject and Email identify the person, from the verified ID token.
	Subject string `json:"subject"`
	Email   string `json:"email,omitempty"`
}

// Store keeps a public client's Credentials between runs.
type Store interface {
	// Load returns the stored credentials, or ErrNotLoggedIn.
	Load(ctx context.Context) (*Credentials, error)
	// Save replaces the stored credentials.
	Save(ctx context.Context, c *Credentials) error
	// Delete removes the stored credentials. Deleting none succeeds.
	Delete(ctx context.Context) error
}

// Locker is implemented by a Store that several processes share, such as
// a command-line tool and an MCP server it started. A Session holds the
// lock while it refreshes: SystemAuth rotates refresh tokens and treats a
// redeemed one presented again as stolen, revoking the whole family, so
// two processes must never redeem the same refresh token.
type Locker interface {
	// Lock waits for the lock and returns the function that releases it.
	Lock(ctx context.Context) (unlock func() error, err error)
}

// FileStore keeps credentials in one JSON file readable by its owner only
// (0600, in a 0700 directory), written atomically. On Unix-like systems it
// refuses a file that others can read, as ssh does for private keys.
type FileStore struct {
	// Path is the credentials file, e.g. a file under
	// os.UserConfigDir(). Required.
	Path string
}

var (
	_ Store  = FileStore{}
	_ Locker = FileStore{}
)

// Load implements Store.
func (f FileStore) Load(_ context.Context) (*Credentials, error) {
	info, err := os.Stat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotLoggedIn
	}
	if err != nil {
		return nil, fmt.Errorf("publicclient: credentials file: %w", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("publicclient: credentials file %s is accessible by others (mode %v); restrict it to its owner (chmod 600)", f.Path, info.Mode().Perm())
	}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("publicclient: reading credentials: %w", err)
	}
	var c Credentials
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("publicclient: decoding credentials %s: %w", f.Path, err)
	}
	return &c, nil
}

// Save implements Store: it writes a temporary file next to Path and
// renames it over Path, so a reader never sees a partial file.
func (f FileStore) Save(_ context.Context, c *Credentials) (err error) {
	b, err := json.MarshalIndent(c, "", "  ") //nolint:gosec // G117: the store's job is to persist these tokens, in an owner-only file
	if err != nil {
		return fmt.Errorf("publicclient: encoding credentials: %w", err)
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("publicclient: credentials directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(f.Path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("publicclient: writing credentials: %w", err)
	}
	defer func() {
		if err != nil {
			if rerr := os.Remove(tmp.Name()); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				err = errors.Join(err, rerr)
			}
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return errors.Join(fmt.Errorf("publicclient: writing credentials: %w", err), tmp.Close())
	}
	if _, err := tmp.Write(b); err != nil {
		return errors.Join(fmt.Errorf("publicclient: writing credentials: %w", err), tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("publicclient: writing credentials: %w", err)
	}
	if err := os.Rename(tmp.Name(), f.Path); err != nil {
		return fmt.Errorf("publicclient: writing credentials: %w", err)
	}
	return nil
}

// Delete implements Store.
func (f FileStore) Delete(_ context.Context) error {
	if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("publicclient: deleting credentials: %w", err)
	}
	return nil
}

// Lock timing: how often a waiting process retries, how long it waits,
// and when a lock left by a process that died counts as stale.
const (
	lockRetry = 50 * time.Millisecond
	lockWait  = 30 * time.Second
	lockStale = time.Minute
)

// Lock implements Locker with a lock file next to Path, created
// exclusively; a lock older than a minute is taken over, since a refresh
// takes seconds and its holder must have died.
func (f FileStore) Lock(ctx context.Context) (func() error, error) {
	if err := os.MkdirAll(filepath.Dir(f.Path), 0o700); err != nil {
		return nil, fmt.Errorf("publicclient: credentials directory: %w", err)
	}
	path := f.Path + ".lock"
	ctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	for {
		lf, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // G304: the lock file sits next to the configured credentials path
		if err == nil {
			if err := lf.Close(); err != nil {
				return nil, errors.Join(fmt.Errorf("publicclient: lock: %w", err), os.Remove(path))
			}
			return func() error {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("publicclient: unlock: %w", err)
				}
				return nil
			}, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("publicclient: lock: %w", err)
		}
		if info, serr := os.Stat(path); serr == nil && time.Since(info.ModTime()) > lockStale {
			if rerr := os.Remove(path); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
				return nil, fmt.Errorf("publicclient: removing a stale lock: %w", rerr)
			}
			continue
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("publicclient: waiting for the credentials lock %s: %w", path, ctx.Err())
		case <-time.After(lockRetry):
		}
	}
}
