package serviceaccount

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/plexusone/systemforge/identity/accesschange"
	"github.com/plexusone/systemforge/identity/credential"
	"github.com/plexusone/systemforge/identity/ent"
	entcredential "github.com/plexusone/systemforge/identity/ent/credential"
	"github.com/plexusone/systemforge/identity/ent/predicate"
)

// Key algorithms a service account key may use.
const (
	AlgorithmES256 = "ES256"
	AlgorithmRS256 = "RS256"
	AlgorithmEdDSA = "EdDSA"
)

// MinRSABits is the shortest RSA key accepted.
const MinRSABits = 2048

// KeyInput describes a key to add. With PublicKeyPEM empty, AddKey
// generates a P-256 key pair and returns the private key once.
type KeyInput struct {
	// PublicKeyPEM is a PEM "PUBLIC KEY" (PKIX) or "RSA PUBLIC KEY"
	// (PKCS #1) block. Empty generates a key pair.
	PublicKeyPEM string
	// Algorithm is ES256 (P-256), RS256 (RSA, 2048 bits or more) or
	// EdDSA (Ed25519). Empty takes it from the key.
	Algorithm string
	// Name labels the key.
	Name string
	// Scopes limit the key; empty means the account's allowed scopes.
	Scopes []string
	// ExpiresAt is when the key stops working; nil means never.
	ExpiresAt *time.Time
}

// Key is a service account key.
type Key struct {
	CredentialID uuid.UUID  `json:"credential_id"`
	KeyID        string     `json:"key_id"`
	Algorithm    string     `json:"algorithm"`
	PublicKeyPEM string     `json:"public_key_pem"`
	Name         string     `json:"name,omitempty"`
	Scopes       []string   `json:"scopes,omitempty"`
	Active       bool       `json:"active"`
	Revoked      bool       `json:"revoked"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP   string     `json:"last_used_ip,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`

	// PrivateKeyPEM is the PKCS #8 private key, set only on the Key AddKey
	// returns for a generated key pair. It is never stored; it is not
	// serialized, so it cannot leak through a JSON listing.
	PrivateKeyPEM string `json:"-"`
}

// Usable reports whether the key can authenticate at now: active,
// unrevoked and unexpired.
func (k *Key) Usable(now time.Time) bool {
	return k.Active && !k.Revoked && (k.ExpiresAt == nil || k.ExpiresAt.After(now))
}

// AddKey registers a public key for the account, or generates a P-256 key
// pair and returns its private key once in Key.PrivateKeyPEM.
func (s *Service) AddKey(ctx context.Context, id uuid.UUID, in KeyInput) (*Key, error) {
	acct, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.ExpiresAt != nil && !in.ExpiresAt.After(s.now()) {
		return nil, fmt.Errorf("%w: expiry is in the past", ErrInvalidKey)
	}
	publicPEM, privatePEM, alg, err := prepareKey(in)
	if err != nil {
		return nil, err
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = acct.AllowedScopes
	}
	kp, err := s.credentials.CreateKeypair(ctx, credential.CreateKeypairInput{
		PrincipalID:  id,
		Name:         in.Name,
		KeyAlgorithm: alg,
		PublicKeyPEM: publicPEM,
		Scopes:       scopes,
		ExpiresAt:    in.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	s.logger.InfoContext(ctx, "service account key added", "principal_id", id, "key_id", kp.KeyID, "algorithm", alg)
	k := fromKeypair(kp)
	k.PrivateKeyPEM = privatePEM
	return k, nil
}

// prepareKey returns the public key PEM to store, the private key PEM when
// it generated the pair, and the algorithm.
func prepareKey(in KeyInput) (publicPEM, privatePEM, alg string, err error) {
	if in.PublicKeyPEM == "" {
		if in.Algorithm != "" && in.Algorithm != AlgorithmES256 {
			return "", "", "", fmt.Errorf("%w: generated keys are P-256 (ES256)", ErrInvalidKey)
		}
		publicPEM, privatePEM, err = generateP256()
		return publicPEM, privatePEM, AlgorithmES256, err
	}
	pub, err := ParsePublicKeyPEM(in.PublicKeyPEM)
	if err != nil {
		return "", "", "", err
	}
	alg, err = keyAlgorithm(pub, in.Algorithm)
	if err != nil {
		return "", "", "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", "", fmt.Errorf("%w: %v", ErrInvalidKey, err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), "", alg, nil
}

// generateP256 makes a P-256 key pair and returns the PKIX public key and
// the PKCS #8 private key, both PEM.
func generateP256() (publicPEM, privatePEM string, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("serviceaccount: generating key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("serviceaccount: encoding private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("serviceaccount: encoding public key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})), nil
}

// ParsePublicKeyPEM parses a PEM "PUBLIC KEY" (PKIX) or "RSA PUBLIC KEY"
// (PKCS #1) block into an *ecdsa.PublicKey, *rsa.PublicKey or
// ed25519.PublicKey.
func ParsePublicKeyPEM(s string) (any, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block", ErrInvalidKey)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return pub, nil
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return pub, nil
	}
	return nil, fmt.Errorf("%w: PEM block %q is not a public key", ErrInvalidKey, block.Type)
}

// keyAlgorithm returns the algorithm for pub: want if it suits the key,
// or the key's own algorithm when want is empty.
func keyAlgorithm(pub any, want string) (string, error) {
	var alg string
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("%w: only P-256 elliptic curve keys are supported", ErrInvalidKey)
		}
		alg = AlgorithmES256
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSABits {
			return "", fmt.Errorf("%w: RSA keys must be at least %d bits", ErrInvalidKey, MinRSABits)
		}
		alg = AlgorithmRS256
	case ed25519.PublicKey:
		alg = AlgorithmEdDSA
	default:
		return "", fmt.Errorf("%w: unsupported key type %T", ErrInvalidKey, pub)
	}
	if want != "" && want != alg {
		return "", fmt.Errorf("%w: algorithm %s does not suit the key (want %s)", ErrInvalidKey, want, alg)
	}
	return alg, nil
}

// ListKeys returns the account's keys, newest first, including revoked
// and expired ones.
func (s *Service) ListKeys(ctx context.Context, id uuid.UUID) ([]*Key, error) {
	if _, err := s.Get(ctx, id); err != nil {
		return nil, err
	}
	kps, err := s.credentials.ListKeypairs(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make([]*Key, len(kps))
	for i, kp := range kps {
		out[i] = fromKeypair(kp)
	}
	return out, nil
}

// RevokeKey revokes one of the account's keys. When it was the account's
// last usable key, a SessionsRevoked access change is recorded with it, so
// tokens issued with it stop at once in applications with a revocation
// cache. Revoking a revoked key does nothing.
func (s *Service) RevokeKey(ctx context.Context, id uuid.UUID, keyID, reason string) error {
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	tx, err := s.client.Tx(ctx)
	if err != nil {
		return fmt.Errorf("serviceaccount: starting transaction: %w", err)
	}
	change, err := s.revokeInTx(ctx, tx, id, keyID, reason)
	if err != nil {
		return errors.Join(err, tx.Rollback())
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("serviceaccount: committing revocation: %w", err)
	}
	if change != nil {
		accesschange.Publish(s.accessSink, *change)
	}
	s.logger.InfoContext(ctx, "service account key revoked", "principal_id", id, "key_id", keyID, "reason", reason)
	return nil
}

// revokeInTx revokes the key and, when no usable key is left, records the
// access change it returns.
func (s *Service) revokeInTx(ctx context.Context, tx *ent.Tx, id uuid.UUID, keyID, reason string) (*accesschange.Change, error) {
	now := s.now()
	cred, err := tx.Credential.Query().
		Where(
			entcredential.PrincipalID(id),
			entcredential.TypeEQ(entcredential.TypeKeypair),
			entcredential.KeyIDEQ(keyID),
		).
		Only(ctx)
	if ent.IsNotFound(err) {
		return nil, fmt.Errorf("%w: %s", ErrKeyNotFound, keyID)
	}
	if err != nil {
		return nil, fmt.Errorf("serviceaccount: reading key: %w", err)
	}
	if cred.Revoked {
		return nil, nil
	}
	wasUsable := cred.Active && (cred.ExpiresAt == nil || cred.ExpiresAt.After(now))
	if err := tx.Credential.UpdateOne(cred).
		SetRevoked(true).
		SetRevokedAt(now).
		SetRevokedReason(reason).
		SetActive(false).
		Exec(ctx); err != nil {
		return nil, fmt.Errorf("serviceaccount: revoking key: %w", err)
	}
	if !wasUsable {
		return nil, nil
	}
	left, err := tx.Credential.Query().Where(usableKeys(id, now)...).Exist(ctx)
	if err != nil {
		return nil, fmt.Errorf("serviceaccount: counting usable keys: %w", err)
	}
	if left {
		return nil, nil
	}
	change, err := accesschange.Record(ctx, tx, accesschange.Change{PrincipalID: id, Reason: accesschange.SessionsRevoked})
	if err != nil {
		return nil, err
	}
	return &change, nil
}

// usableKeys selects the account's usable key-pair credentials at now.
func usableKeys(id uuid.UUID, now time.Time) []predicate.Credential {
	return []predicate.Credential{
		entcredential.PrincipalID(id),
		entcredential.TypeEQ(entcredential.TypeKeypair),
		entcredential.Active(true),
		entcredential.Revoked(false),
		entcredential.Or(entcredential.ExpiresAtIsNil(), entcredential.ExpiresAtGT(now)),
	}
}

func fromKeypair(kp *credential.KeypairCredential) *Key {
	k := &Key{KeyID: kp.KeyID, Algorithm: kp.KeyAlgorithm, PublicKeyPEM: kp.PublicKeyPEM}
	if c := kp.Credential; c != nil {
		k.CredentialID = c.ID
		k.Name = c.Name
		k.Scopes = c.Scopes
		k.Active = c.Active
		k.Revoked = c.Revoked
		k.ExpiresAt = c.ExpiresAt
		k.RevokedAt = c.RevokedAt
		k.LastUsedAt = c.LastUsedAt
		k.LastUsedIP = c.LastUsedIP
		k.CreatedAt = c.CreatedAt
	}
	return k
}
