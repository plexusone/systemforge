# Key Management

SystemForge encrypts stored secrets under keys it manages through
[keyforge](https://github.com/plexusone/keyforge), so that keys rotate without
re-encrypting data, a key's use is audited, and the root key is read from your
secret store rather than kept beside the data. The design is
[ADR-013](../design/adrs/ADR-013-key-management.md).

!!! warning "Pre-release"
    keyforge has not been externally audited and is not yet recommended for
    production use. Read its [threat model](https://github.com/plexusone/keyforge/blob/main/docs/threat-model.md)
    before relying on it for data under legal hold.

## What uses it

The `keys` package is the platform's one key library. Today SystemAuth uses it
to seal the credentials of [connections to external services](connections.md).
Applications can use it for their own data through the same interface.

## How it is laid out

| Piece | Where it lives |
|---|---|
| **Root key** | Your secret store, read through [omnivault](https://github.com/plexusone/omnivault) when the process starts. It is 32 random bytes, as base64 or hex |
| **Key ring** | A file in the keys directory, sealed under the root key |
| **Registry** | A SQLite database in the same directory: key versions, data keys and their states |
| **Data** | Your database, holding ciphertext that names the key version that sealed it |

The key ring and the registry sit in one directory on purpose: they are backed
up together, so a restore never pairs a registry with a key ring from another
moment.

## Set it up

For a SystemAuth deployment, the `connections` section configures it (see
[Connections](connections.md)):

```yaml
connections:
  keys_dir: /var/lib/systemauth/keys   # the key ring and registry
  vault: env://                        # omnivault URI: env://, file:///dir, ...
  root_key: SYSTEMAUTH_KEYS_ROOT       # the root key's path in that vault
```

Create the root key once, store it in the secret store, and keep a second copy
offline. It is not recoverable:

```bash
export SYSTEMAUTH_KEYS_ROOT="$(openssl rand -base64 32)"
```

keyforge refuses a root key that is a file kept inside the keys directory, so
the key never sits beside what it protects.

## Use it from Go

```go
v, err := omnivault.VaultFromURI("env://")
if err != nil {
	return err
}
k, err := keys.Open(ctx, keys.Options{
	Dir:      "/var/lib/myapp/keys",
	Root:     keys.VaultSource(v, "MYAPP_KEYS_ROOT"),
	Purposes: []keyforge.Purpose{"myapp.sessions"},
	Audit:    auditStore, // optional: key events go to the platform audit trail
})
if err != nil {
	return err
}
defer k.Close()

sealed, err := k.Seal(ctx, "myapp.sessions", []byte("value"), []byte("user:42"))
plain, err := k.Open(ctx, "myapp.sessions", sealed, []byte("user:42"))
```

- **Purpose** names what a key protects. Each purpose gets its own keys, so
  exposing or destroying one does not touch another.
- **The additional data** (`"user:42"` above) is bound to the ciphertext. It
  must be the same to open it, so a value cannot be moved to another record.
- **`Open` fails closed.** With no usable key it returns an error; it never
  falls back to something weaker.
- **Run the lifecycle jobs.** `k.Run(ctx)` rotates keys on schedule and
  resumes unfinished work after a restart. `systemauth serve` does this for
  you.

## What it does for you

- **Rotation without re-encrypting.** Rotating a key-encryption key re-wraps
  data keys. Stored ciphertext is not rewritten, and old versions stay
  readable until nothing references them.
- **Audit.** When you pass `Audit`, key creation, rotation, retirement and
  destruction are recorded in the platform audit trail with no key material.
  Ordinary seal and open are not logged one by one. Without an audit
  store, `keys.Options.Logger` logs the same events instead. A host that
  embeds SystemAuth passes `systemauthsvc.Options.AuditStore` to record key
  and connection events in its audit trail; the `systemauth` command passes
  none, so it logs them.
- **Backup checks.** A key ring restored from a backup older than one this
  host has seen is refused unless `keys.Options.AcceptRollback` is set, so a
  stale copy is never used by mistake.

## Operate it

| Task | How |
|---|---|
| Back up | Stop the process, copy the whole keys directory, and keep the root key separately. The key ring and the registry must come from the same moment |
| Restore or move | Stop the process, restore or copy the directory, and open with `keys.Options.AcceptRollback` once. This is needed for a ring older than one this host has seen, a ring moved to a new host without its rollback state, and once after upgrading from a release whose rollback state was not authenticated. For SystemAuth, run `systemauth keys accept-rollback --confirm` with the server's configuration, then start the server as usual; a host that embeds SystemAuth calls `systemauthsvc.AcceptKeyRollback` |
| Upgrade to SystemForge v0.21.0 | keyforge v0.2.0 authenticates the rollback state, so an existing keyring refuses to open after the upgrade. Stop the server, run `systemauth keys accept-rollback --confirm --config <path>` once, then start it |
| Check status or rotate by hand | Not served yet. SystemAuth runs the lifecycle jobs but does not mount keyforge's control plane or command line |
| Move the registry to PostgreSQL | Not yet: this release uses keyforge's single-host setup. ADR-013 records the follow-up |

Signing keys, client secrets, session sealing keys and SCIM tokens are not
keyforge keys; they rotate by keeping the current and previous value valid.
See [Rotating keys and secrets](rotation.md).

## Limits to know

- **The local provider is as safe as the host and its root key source.** It is
  not a hardware module. A managed key service is the recommended root of
  trust for data under legal hold.
- **A restore can undo an erasure.** Shredding lives in the registry, and
  backups hold destroyed versions' material.
- **One process owns the directory.** Run the jobs in one process, or share a
  workflow provider; do not point two processes at the same directory.
