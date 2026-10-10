# ADR-013: Key Management

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-012 (snapshots and held data are encrypted under keys this
ADR manages), ADR-011 (erasure and its strategies).
**Updates:** a new `docs/design/architecture/key-management.md`.

## Context

SystemForge already encrypts data in more than one place, each with its own
small mechanism: sealed session secrets in the relying-party store, the BFF
session cookie encryption, and signing keys for tokens. ADR-012 adds
sealed snapshots under legal hold, which may live in the database or an
object store and must survive for as long as a hold lasts.

Those uses share needs that ad hoc code does not meet: rotation without
re-encrypting everything, a record of which key protected which data, a
choice of where root keys live, and, for privacy, the ability to make data
unrecoverable on purpose. A platform that promises erasure has to answer
what happens to backups and replicas of erased data. Encrypting personal data
under a key that can itself be destroyed answers that, and so key management
is part of the privacy design, not a separate concern.

Many SystemForge businesses start as a single person on one host, and some
will run in a cloud with a managed key service. The design has to work with
a local file key on day one and with a managed service later, without
changing the data.

## Decision

1. **SystemForge has one key management package** (`keys`) that every
   encryption use in the platform goes through, replacing the per-package
   mechanisms over time. Applications use it for their own data through the
   same interface.
2. **Envelope encryption.** Data is encrypted with a data key (DEK);
   DEKs are encrypted (wrapped) by a key-encryption key (KEK) held by a
   `KeyProvider`. Ciphertext carries the identifier and version of the key
   that wrapped it, so any record can be decrypted, rotated or destroyed
   knowing only what is stored beside it.
3. **Providers are pluggable.** A provider wraps and unwraps and never
   exposes a KEK. Initial providers: a local provider (a key file or
   environment-supplied key, for development and single-host deployments)
   and a cloud KMS provider interface with a first implementation for the
   hosting target. A deployment selects the provider by configuration.
   The local provider is marked as such in the catalog and in startup logs,
   so it is not mistaken for a managed one.
4. **Keys are scoped by purpose.** Separate keys for session secrets,
   token signing, snapshots, and per-product data, so exposure or
   destruction of one does not touch the others. Purpose is part of the key
   identity and of the encryption context bound to each ciphertext.
5. **Rotation re-wraps, it does not re-encrypt.** Rotating a KEK re-wraps
   its DEKs; rotating a DEK applies to new data and to data re-encrypted on
   write or by a background job. Old versions stay available for decryption
   until nothing references them.
6. **Crypto-shredding is a supported erasure strategy.** An entity may be
   registered with a per-subject DEK (ADR-011's erasure strategies gain
   `shred`): erasure destroys that subject's DEK, which makes the subject's
   ciphertext unrecoverable everywhere it was copied, including backups.
   This is an option for data too widespread to rewrite, not the default.
7. **Holds protect keys as well as data.** A key that protects data under a
   hold cannot be destroyed while any hold covers the subject (ADR-012),
   and destruction is a request with the delay or approval policy of
   ADR-012's decision 11.
8. **Key use and lifecycle are audited.** Creation, rotation, wrapping
   failures, access by an administrator and destruction are recorded
   without key material. Ordinary encrypt and decrypt are not logged one by
   one; rates and failures are metered.
9. **Snapshot keys.** Snapshots are encrypted under a purpose key for
   snapshots with a DEK per hold (so releasing a hold and erasing its
   snapshots can destroy that DEK). A per-subject DEK is added when a
   subject's data participates in more than one hold or when crypto-shredding
   is selected for the subject.

## Consequences

- **One place to rotate, audit and replace keys,** instead of several
  private mechanisms.
- **Erasure that covers backups** is available for the data that needs it,
  at the cost of managing per-subject keys.
- **A single-person business can start with a file key** and move to a
  managed key service by configuration, without rewriting stored data.
- **The platform takes on the operational duty** of protecting root keys.
  The local provider is only as safe as the host; the documentation says
  so and recommends a managed provider for any deployment holding data under
  hold.
- **Migration work:** existing sealed secrets and signing keys move onto
  the package incrementally, each behind its own change.

## Alternatives considered

- **Leave each package to manage its own keys.** Rejected: rotation and
  audit cannot be done consistently, and erasure cannot reach backups.
- **Require a cloud KMS everywhere.** Rejected: excludes single-host and
  local development, and ties the platform to one vendor.
- **Encrypt the database as a whole only.** Insufficient: it does not give
  per-purpose or per-subject destruction, and it does not protect exports,
  snapshots or object-store files.

## Open questions

- Which KMS provider to implement first.
- How per-subject keys are stored and cached so that reads stay fast.
- Whether the key package also provides signing-key management for tokens
  in its first version, or only data encryption.
- Key escrow and recovery for the local provider.
- Interaction with the database's own encryption at rest and with customers
  who bring their own keys.
