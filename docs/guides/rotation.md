# Rotating Keys and Secrets

Every key and secret SystemForge verifies rotates the same way: the current
value N and the previous value N-1 are both valid, and a rotation retires
only N-2. A rotation therefore never signs anybody out, and rolling back a
deploy always returns to a configuration that still accepts everything
issued so far. This page is the runbook; each section links to the full
reference.

## The rule

1. **Pre-stage.** Make the new value N known to every verifier while N-1
   is still the one in use. Wait until every instance runs it.
2. **Promote.** Start using N. Keep N-1 valid.
3. **Verify.** Confirm N works everywhere: tokens verify, clients
   authenticate, sessions open, provisioning succeeds.
4. **Retire.** Drop N-1 only once nothing still needs it (its tokens have
   expired, every caller uses N), or leave it for the next rotation, which
   drops it as N-2.

Never introduce a new value and drop the previous one in the same deploy:
a rollback would then reject everything the new value produced.

| What | Where it is set | Pre-staged? | Reference |
|---|---|---|---|
| SystemAuth signing key | `keys.key_id`, `keys.verification_keys` | Yes | [Deploying SystemAuth](../systemauth/deployment.md#rotating-the-signing-key) |
| `identity/oauth` signing key | `Config.KeyID`, `Config.VerificationKeys` | Yes | [DPoP Enforcement](../session/dpop.md#the-identityoauth-provider) |
| `session/jwt` keys | `jwt.Config.KeyID`, `VerificationKeys` | Yes | [JWT Audience](../bff/audience.md#key-rotation) |
| OAuth client secrets | `EntStorage.RotateClientSecret` | No: N and N-1 both authenticate | [OAuth Apps](../oauth/apps.md#rotate-secret) |
| BFF session sealing keys | `bff.NewKeyringSealer`, or `bff.NewKeysSealer` | Yes | [BFF Sessions](../session/bff-sessions.md#rotating-keyring-keys), [Ent Store](../bff/ent-store.md#key-rotation) |
| SCIM tenant tokens | `scimtoken` `Rotate`, or `POST .../scim-tokens/rotate` | No: N and N-1 both authenticate | [SCIM Provisioning](../identity/scim.md#issue-rotate-and-revoke) |
| Connections key ring | keyforge, on schedule | Automatic | [Key Management](key-management.md) |

## SystemAuth signing keys

Tokens carry the `kid` of the key that signed them, and a token with an
unknown `kid` is refused.

1. Generate key N and add it to `keys.verification_keys` while N-1 signs.
   Relying parties see it in the JWKS before any token signed with it
   exists.
2. Make N the signing key (`keys.private_key_file` or `private_key_pem`,
   and `keys.key_id`), and move N-1 into `keys.verification_keys`. Drop
   N-2.
3. Check that new tokens carry the new `kid` and that relying parties
   accept them.
4. Keep N-1 listed until the longest-lived token it signed has expired:
   ID tokens (1 hour by default) and JWT access tokens (at most 15
   minutes).

```yaml
keys:
  private_key_file: /etc/systemauth/signing-3.pem   # N, signing
  key_id: signing-3
  verification_keys:
    - key_id: signing-2                               # N-1
      public_key_file: /etc/systemauth/signing-2.pem
```

The `identity/oauth` provider and `session/jwt` follow the same steps with
their own `KeyID` and `VerificationKeys`. For `session/jwt`, give the
current key a `KeyID` first and wait until tokens issued without one have
expired before the first rotation.

## OAuth client secrets

A confidential client authenticates with its two newest active secrets.
`EntStorage.RotateClientSecret` issues N, keeps N-1 and revokes anything
older in one step:

```go
rotated, err := storage.RotateClientSecret(ctx, "reporting-service")
if err != nil {
	return err
}
// rotated.Secret is shown once: hand it to the client's secret store.
```

1. Rotate, and deploy the new secret to the client.
2. Watch the client authenticate with it.
3. End the overlap with `RevokeClientSecret(ctx, clientID, previousID)`, or
   leave N-1 for the next rotation. If the new secret is bad, revoke it
   instead: N-1 is current again.

A client listed under `clients` in the SystemAuth configuration file is
created from its `secret` the first time SystemAuth starts with a
database. Later starts update the client's other settings but not its
secret, so rotate that client's secret with `RotateClientSecret` too
rather than by editing the file.

## BFF session sealing keys

Session secrets (tokens and DPoP private keys) are sealed under a key ID,
and each sealed value names its key. With `bff.NewKeyringSealer`, rotate in
separate deploys:

```go
// 1. Pre-stage k2 while k1 stays active.
sealer, err := bff.NewKeyringSealer("k1", map[string][]byte{"k1": k1, "k2": k2})
// 2. Promote k2 and keep k1.
sealer, err = bff.NewKeyringSealer("k2", map[string][]byte{"k1": k1, "k2": k2})
// 3. Next rotation: pre-stage k3 with k1 still present, then promote k3
//    with {"k2": k2, "k3": k3}.
```

Sessions are sealed again under the active key whenever they are updated,
for example on token refresh. Sessions still sealed with N-2 when it is
removed no longer open, and their users sign in again.
`bff.NewKeysSealer` seals with a keyforge purpose key instead, which
versions and rotates its keys itself.

## SCIM tenant tokens

An organization has at most two valid SCIM tokens, the current one and the
previous one. Organization owners and admins rotate them through
`/api/v1/organizations/{slug}/scim-tokens` with an access token granted
`systemforge:scim_tokens`:

1. `POST /api/v1/organizations/{slug}/scim-tokens/rotate`. The response
   carries the new token once, and lists any tokens the rotation revoked
   (N-2 and older).
2. Configure the identity provider with the new token and watch
   provisioning succeed. If it fails, revoke the new token
   (`DELETE .../scim-tokens/{token_id}`); the previous one is current
   again.
3. Revoke the previous token once the switch is confirmed, or leave it for
   the next rotation.

`GET .../scim-tokens` lists each token's status (`current`, `previous`,
`revoked`, `expired` or `superseded`) and when it was last used.

## Keys that are not rotated this way

- **The connections key ring.** keyforge rotates its keys on schedule
  without re-encrypting data; see [Key Management](key-management.md).
  After restoring or moving the keys directory, or once after upgrading to
  v0.21.0, run `systemauth keys accept-rollback --confirm`.
- **A relying party's DPoP key** (`relyingparty.Config.DPoPKey`). Tokens
  and refresh tokens are bound to it, so sessions holding tokens bound to
  the old key cannot refresh them, and their users sign in again.
