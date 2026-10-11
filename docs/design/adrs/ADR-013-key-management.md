# ADR-013: Key Management

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-012 (snapshots and held data are encrypted under keys this
ADR manages), ADR-011 (erasure and its strategies).
**Builds on:** [keyforge](https://github.com/plexusone/keyforge), the generic
key-lifecycle library and control plane whose
[specifications](https://github.com/plexusone/keyforge/tree/main/docs/specs)
define the mechanism.
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
changing the data. Because none of this is specific to identity, the
mechanism is its own module, keyforge, usable by every PlexusOne product.

## Decision

Key management is a generic capability, so its mechanism lives in a
separate module, keyforge, and not in SystemForge. This ADR records what
SystemForge decides on top of it: that the platform uses keyforge for every
encryption need, the policy it applies, and the points where platform policy
(holds, approvals, roles, the catalog) plugs into it. Decisions 2 to 6 and 10
to 13 state the platform's requirements; keyforge's technical requirements
specify how they are met, and where the wording differs the keyforge
specification governs the mechanism while this ADR governs the policy.

1. **SystemForge adopts keyforge as its one key library and control
   plane.** Every encryption use in the platform goes through it, replacing
   the per-package mechanisms over time; applications use it for their own
   data through the same interface. SystemForge provides a thin `keys`
   package that wires keyforge to the platform:
   - **Store:** the keyforge registry runs on SystemForge's database through
     Ent (SQLite or PostgreSQL), in the same deployment as everything else.
   - **Guard:** keyforge's `DestroyGuard` is implemented from ADR-012: holds
     protect keys (decision 7), and destruction follows the platform's delay
     or approval policy. keyforge does not know about holds.
   - **Audit:** keyforge's audit events flow into the platform audit trail
     (decision 8).
   - **Authorizer:** control-plane actions are authorized by SystemForge's
     authorization, with the `privacy_manager` and `legal_manager` roles of
     ADR-012 where the action concerns erasure or held data.
   - **Catalog:** an entity registered in the data catalog (ADR-012) states
     its data-key granularity (decision 10), and the catalog is the inventory
     of which data a purpose protects.
   - **Root key:** the local provider's root key is read through omnivault,
     so a deployment supplies it from its secret manager.
   - **Mounting:** the keyforge control plane is mounted in the same
     process, like SystemAuth, and split out only when another process needs
     it. Encrypt and decrypt stay in process and make no network call.
2. **Envelope encryption.** Data is encrypted with a data key (DEK);
   DEKs are encrypted (wrapped) by a key-encryption key (KEK) held by a
   `KeyProvider`. Ciphertext carries the identifier and version of the key
   that wrapped it, so any record can be decrypted, rotated or destroyed
   knowing only what is stored beside it.
3. **Providers are pluggable.** A provider wraps and unwraps and never
   exposes a KEK. The KEK may be a symmetric key or an asymmetric keypair;
   `Wrap` and `Unwrap` are the same either way (decision 11). Initial providers: a local provider (a key file or
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
   until nothing references them. Rotation is online and needs no downtime:
   ciphertext carries the key version that wrapped it, so old and new
   versions are read side by side. Schedule and procedure are decision 12.
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
10. **Data keys have a configurable granularity,** chosen when an entity
    or store is registered:

    | Granularity | Fits | Cost |
    |---|---|---|
    | Per object | Files, exports, snapshots; erasing one object is trivial | One wrap and unwrap per read; with a remote KMS, a call per read unless the unwrapped key is cached |
    | Per subject or per hold | Rows tied to a person or a hold (decision 9) | Erasure or release destroys one key |
    | Per purpose | High-volume, low-sensitivity data such as sessions | A cap on encryptions per key (decision 12) |

    There is no single default: the registration states one, and the catalog
    (ADR-012) records it.
11. **Bulk data is never encrypted directly with an asymmetric key.** An
    asymmetric KEK is used as a hybrid: a random symmetric data key
    (AES-256-GCM) encrypts the data and is wrapped to the public key (RSA-OAEP
    or HPKE), with the wrapped key stored beside the ciphertext; reading
    unwraps with the private key, then decrypts. Asymmetric KEKs are for
    components that must encrypt without being able to decrypt, such as hold
    snapshots and exports sealed to a key held in a managed service or offline.
    Symmetric KEKs from a managed service or the local provider are the
    default for ordinary platform data. Rotating an asymmetric KEK creates a
    new keypair and keeps old private versions for decryption, subject to
    decision 7.
12. **Rotation is automatic, with defaults by key type.** Each is
    configurable per purpose.

    | Key | Default | Notes |
    |---|---|---|
    | KEK | 365 days; floor 90 | Re-wraps data keys; no data is re-encrypted |
    | Data key | New key every 90 days or after N encryptions per purpose, whichever is first | Applies to new writes; old data is re-encrypted lazily on write, or by a throttled, resumable background job after a compromise or policy change |
    | Token signing key (if in scope, see open questions) | 90 days, with a published overlap longer than relying parties' JWKS cache time | |
    | Snapshot, per-hold and per-subject keys | Never by schedule | Destroyed by release or erasure (decisions 6 and 9) |

    - A managed provider rotates automatically. The local provider rotates
      automatically only after its keyring is verified as backed up;
      otherwise it warns and requires an operator `keys rotate`, because a
      restored backup that predates a rotation would lose everything wrapped
      under the newer version. `keys status` flags a keyring not backed up
      since its last rotation.
    - Rotation never deletes old versions. Retirement is a separate step with
      its own delay, and never while a hold covers the data (decision 7).
    - The last two versions, the active one and its predecessor, are always
      kept, so a bad rotation can be rolled back. Older versions retire only
      when nothing references them, the delay has passed, no hold applies and
      the guard allows it; the count is a floor, not a trigger to delete.
    - A failed or overdue rotation raises an alert; a key past its period is
      reported, not silently kept.
    - Real keys are not rotated weekly. A weekly **rotation drill** runs the
      full lifecycle on a built-in canary purpose that holds no data, so the
      mechanism is exercised and its failures surface within a week, without
      the version churn and keyring-backup burden of rotating real keys that
      often.
13. **Emergency rotation is a separate procedure from scheduled rotation.**
    If a KEK is compromised, re-wrapping is not enough: the old KEK version
    is destroyed (subject to holds, with the approval path of ADR-012's
    decision 11 available but not blocking an emergency) and the data keys
    are rotated. If a data key is exposed, its data is re-encrypted under a
    new key. Both are audited, and the procedure is documented with the
    provider.
14. **Post-quantum algorithms are adopted from the Go standard library as
    they appear, hybrid first.** The standard library now provides ML-KEM
    (`crypto/mlkem`, FIPS 203), HPKE with ML-KEM and hybrid KEMs
    (`crypto/hpke`, which adds `MLKEM768X25519` and `MLKEM768P256`), and ML-DSA
    (`crypto/mldsa`, FIPS 204). The platform's position is:
    - **Symmetric keys need no change.** AES-256-GCM encryption and key
      wrapping are already adequate against a quantum adversary, so KEKs and
      DEKs under decision 2 stay as they are.
    - **Asymmetric KEKs are hybrid.** When asymmetric KEKs are introduced
      (decision 11) the default KEM is a hybrid of a classical and a
      post-quantum scheme through `crypto/hpke`, not a classical-only one.
      Long-lived confidentiality, such as hold snapshots, exports and backups,
      is exposed to harvest-now-decrypt-later, and these are the uses that
      justify it first.
    - **Signatures follow ecosystem support.** Signing keys (decision 12) move
      to ML-DSA, or a hybrid, when the formats that carry them (token and key
      set specifications) and the relying parties support it. Until then they
      stay on Ed25519 or ECDSA.
    - **Standard library only.** No third-party post-quantum implementation
      is used. The envelope's algorithm identifier makes each of these a
      format addition, not a change to stored data.
15. **FIPS 140-3 operation is supported and tested, and is the default
    posture for a production deployment that has no reason to leave it.**
    The Go standard library includes a FIPS 140-3 cryptographic module,
    selected at build time (`GOFIPS140`) and enabled at run time
    (`GODEBUG=fips140=on`, or `only` to make non-approved algorithms fail).
    - **keyforge and the `keys` package must run under `fips140=only`.**
      Only approved constructions are used on the default paths: AES-256-GCM
      through `cipher.NewGCMWithRandomNonce` (the only GCM constructor that
      mode permits), HKDF and HMAC with SHA-2, ECDSA, Ed25519, RSA-OAEP, and
      ML-KEM. Non-approved options, such as ChaCha20-Poly1305 or X25519, are
      never the default, are isolated behind an explicit option, and are
      refused in `only` mode. Conformance tests run in a FIPS-only
      configuration.
    - **Build and run with the validated module where compliance matters.**
      A build that pins the certified module version has validation
      evidence; a build using the in-tree module in FIPS mode has the same
      behavior without it. The deployment records which it uses, and `status`
      reports it.
    - **Reasons to run outside FIPS mode are stated, not assumed away:**
      a dependency that needs a non-approved algorithm, a module version that
      lacks an algorithm the deployment wants (the validated v1.0.0 module has
      no ML-DSA), or a development environment. Leaving FIPS mode is a
      configuration decision recorded in the deployment, not a code path.
    - **FIPS is a constraint, not a security guarantee.** It validates a
      module on tested platforms; it does not cover the rest of an
      application. This ADR does not claim a deployment is "FIPS compliant".
16. **Algorithms are a platform policy that keyforge owns.**
    - **Everything goes through keyforge.** Every protection of stored data
      and of keys uses an algorithm from keyforge's registry. Platform and
      application packages do not choose or call primitives for that purpose.
      Transport security (TLS) and password hashing are outside this rule and
      are decided where they live.
    - **Algorithms are named exactly.** A mode and a size are always stated:
      "AES-256-GCM", never "AES-256", because the bare name does not say
      whether the mode authenticates. Specifications, configuration, logs and
      the ciphertext's algorithm identifier all carry the full name.
    - **The floor is an authenticated mode.** AES-256-GCM is the floor for
      encrypting data and wrapping keys. ECB, CBC, CTR and any unauthenticated
      mode are never offered. "Better" means an authenticated algorithm added
      to the registry from the standard library (or `golang.org/x/crypto`
      where the standard library has none), after review.
    - **Two profiles, `fips` and `standard`.** Each is a fixed, reviewed set of
      algorithms compiled into keyforge. `fips` contains only algorithms the
      Go cryptographic module approves; `standard` adds non-approved ones
      (for example ChaCha20-Poly1305). A process selects its profile from its
      FIPS mode by default; configuration may narrow a profile (deny an
      algorithm, or run the `fips` profile outside FIPS mode) and may never
      widen it.
    - **The sets are code, not configuration.** Acceptable algorithms change
      rarely, and the standard library's set changes with Go releases. Hard-
      coding the profiles keeps them reviewable and keeps the platform's
      claims truthful. Adding an algorithm is a keyforge release, with the
      envelope identifier and vectors that implies.
    - **Reads follow the profile.** A process in the `fips` profile refuses to
      decrypt an envelope that used a non-approved algorithm, with a typed
      error that says so, and the data is migrated by re-encrypting it in a
      `standard` process. A purpose may pin its profile, so data meant for a
      FIPS deployment is never written with a non-approved algorithm.
17. **keyforge is the single system of record for the platform's
    cryptographic choices, and it feeds the crypto specification.**
    - **Authoritative for what it selects and enforces.** The algorithms,
      profiles, purposes, keys, versions, providers and rotation state that
      keyforge governs are facts keyforge owns. They are not restated by hand
      anywhere else.
    - **Reference for what it does not control.** Cryptography configured
      elsewhere, such as edge TLS at a CDN or TLS between internal services,
      may be registered in keyforge as external boundaries, so that there is
      one place to answer "what cryptography do we rely on". A registered
      boundary carries the **expectation** (for example minimum protocol
      version, permitted suites, key exchange groups, certificate key
      strength), an owner, where the real configuration lives, and a review
      date. keyforge records the expectation and does not claim to enforce it.
    - **The system's crypto specification is generated, not written.**
      keyforge exports the facts it owns and the external boundaries it holds
      as a `systemspec-crypto` document. Enforced facts carry evidence from
      keyforge's own configuration and runtime state; declared external facts
      are marked as attested or awaiting review, with the owner and review
      date; a declaration past its review date drops out of "verified".
    - **Verification is a separate step.** Test applications and scanners
      exercise the deployed system and compare what they observe with the
      generated specification and the registered expectations. A scan result
      is evidence attached to a claim, not an edit to the inventory. A
      mismatch is a finding. keyforge is not a scanner.
    - **Metadata only.** The export never contains key material or secret
      values, and a use of a primitive outside keyforge is found by source and
      dependency analysis rather than assumed absent.
18. **Recovery is proven by an automated drill, and judgment is by agents.**
    - A recovery drill restores the registry and keyring from backup into an
      isolated environment, decrypts a sentinel for every retained key version,
      measures recovery time and recovery point against configured limits,
      runs negative checks that must fail, and destroys the environment. It
      runs quarterly and after any change to the provider or backups, with no
      person involved.
    - **Objective results are the engine's** and are final. **Judgments** such
      as severity, trends against earlier drills, likely cause and
      recommendations are written into a DR report by an analyst agent that
      receives metadata only, never key material, plaintext or access to the
      restored environment.
    - The report is evidence for the system's crypto specification: objective
      results are `verified`; the analyst's conclusions are `inferred` until
      someone attests them, and the analyst cannot change policy or key state.

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
- **A dependency on keyforge, and a control plane to run.** The registry
  adds tables, an admin API and a CLI that need the same care as SystemAuth,
  but only the library is on the data path.
- **Rotation needs no downtime and no cutover**, at the cost of keeping old
  key versions until nothing references them.
- **Migration work:** existing sealed secrets and signing keys move onto
  the package incrementally, each behind its own change.
- **Compliance-driven deployments are first-class.** Running under FIPS mode
  is a tested configuration, so a customer that requires it is a
  configuration change, not a fork.
- **Some existing choices are outside FIPS-approved algorithms.** The
  identity credential service hashes passwords with Argon2id, which is not an
  approved algorithm and is not part of the standard library's module. A
  deployment that must use only approved algorithms needs a PBKDF2 option
  there; that is a separate change to the credential service and is not
  decided here.
- **Hybrid post-quantum KEMs carry a classical component.** Where that
  component is X25519, FIPS-only mode refuses it, so such a deployment
  selects a hybrid built on a NIST curve (`MLKEM768P256`).

## Alternatives considered

- **Leave each package to manage its own keys.** Rejected: rotation and
  audit cannot be done consistently, and erasure cannot reach backups.
- **Build the mechanism inside SystemForge.** Rejected: it is not specific
  to identity, other products need it, and key custody deserves its own
  small, separately reviewed module.
- **Require a cloud KMS everywhere.** Rejected: excludes single-host and
  local development, and ties the platform to one vendor.
- **A remote key service on the data path.** Rejected: it adds latency and
  an availability dependency to every read and write. Keys are unwrapped
  once and cached in process.
- **Encrypt bulk data directly with an asymmetric key.** Rejected:
  payload limits and cost; hybrid encryption (decision 11) gives the same
  separation of encrypt and decrypt.
- **Encrypt the database as a whole only.** Insufficient: it does not give
  per-purpose or per-subject destruction, and it does not protect exports,
  snapshots or object-store files.

## Open questions

- Which KMS provider to implement first, and whether it supports ML-KEM or
  hybrid wrapping natively.
- Which hybrid KEM is the default outside FIPS mode and which inside it, and
  when asymmetric KEKs ship.
- How per-subject keys are stored and cached so that reads stay fast.
- Whether the key package also provides signing-key management for tokens
  in its first version, or only data encryption. Decision 12 gives the
  rotation policy that would apply if it does.
- The default `N` for the encryptions-per-key cap, and the default delay
  before a retired key version is destroyed.
- Key escrow and recovery for the local provider.
- Interaction with the database's own encryption at rest and with customers
  who bring their own keys.
