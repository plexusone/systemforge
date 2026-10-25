package oauth

import (
	"crypto/rsa"
	"fmt"
	"slices"

	"github.com/ory/fosite"

	"github.com/plexusone/systemforge/identity/dpopproof"
	"github.com/plexusone/systemforge/identity/internal/oauthcore"
	"github.com/plexusone/systemforge/identity/systemauth"
)

// bindDPoP applies the DPoP policy to a parsed token request and binds the
// tokens it issues to the proof's key (see oauthcore.BindDPoPGrant). A
// client must send a proof unless it is registered with the
// allow_bearer_tokens exception.
func bindDPoP(ar fosite.AccessRequester, proof *dpopproof.Proof) error {
	sess, ok := ar.GetSession().(*systemauth.Session)
	if !ok || sess.DefaultSession == nil {
		return fosite.ErrServerError.WithHint("unexpected session type")
	}
	return oauthcore.BindDPoPGrant(&sess.DPoPJKT, proof, requiresDPoP(ar.GetClient()))
}

// sessionDPoPJKT returns the DPoP binding of a provider session: the
// thumbprint of the key it is bound to, or "" for an unbound session or
// a session of another type.
func sessionDPoPJKT(sess fosite.Session) string {
	if s, ok := sess.(*systemauth.Session); ok && s != nil {
		return s.DPoPJKT
	}
	return ""
}

// newKeyRing returns the key ring that signs with signing, published under
// signingKID (its RFC 7638 thumbprint when empty), and verifies also with
// the verification keys: the previous signing key N-1 after a rotation,
// or a pre-staged next key. Each verification entry has exactly one of
// PublicKey, PublicKeyPEM or PublicKeyFile; its KeyID defaults to the
// key's thumbprint. No two keys may share a kid.
func newKeyRing(signing *rsa.PrivateKey, signingKID string, verification []systemauth.VerificationKeyConfig) (*oauthcore.KeyRing, error) {
	if signing == nil {
		return nil, fmt.Errorf("%w: no signing key", systemauth.ErrInvalidSigningKey)
	}
	if signingKID == "" {
		kid, err := systemauth.KeyThumbprint(signing)
		if err != nil {
			return nil, err
		}
		signingKID = kid
	}
	keys := systemauth.KeyConfig{VerificationKeys: slices.Clone(verification)}
	if err := keys.LoadVerificationKeys(signingKID); err != nil {
		return nil, err
	}
	loaded := make([]oauthcore.VerificationKey, 0, len(keys.VerificationKeys))
	for _, v := range keys.VerificationKeys {
		loaded = append(loaded, oauthcore.VerificationKey{KeyID: v.KeyID, PublicKey: v.PublicKey})
	}
	return oauthcore.NewKeyRing(signing, signingKID, loaded), nil
}
