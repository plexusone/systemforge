package pgstore

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

func randomKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

func mustKeyring(t *testing.T, opts ...Option) *keyring {
	t.Helper()
	kr, err := newKeyring(newConfig(opts))
	if err != nil {
		t.Fatalf("newKeyring: %v", err)
	}
	return kr
}

func TestKeyringRoundTrip(t *testing.T) {
	kr := mustKeyring(t, WithEncryptionKey("k1", randomKey(t)))
	plain := []byte(`{"refreshToken":"secret"}`)
	id, sealed, err := kr.seal("t", "row", plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if id != "k1" || bytes.Contains(sealed, []byte("secret")) {
		t.Fatalf("seal id=%q leaked plaintext=%v", id, bytes.Contains(sealed, []byte("secret")))
	}
	got, err := kr.open("t", "row", id, sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open = %q, %v", got, err)
	}
	// Fresh nonce per seal.
	_, sealed2, err := kr.seal("t", "row", plain)
	if err != nil || bytes.Equal(sealed, sealed2) {
		t.Fatalf("ciphertexts repeat (err %v)", err)
	}
}

func TestKeyringTamperDetection(t *testing.T) {
	kr := mustKeyring(t, WithEncryptionKey("k1", randomKey(t)), WithDecryptionKey("k0", randomKey(t)))
	id, sealed, err := kr.seal("t", "row", []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	for i := range sealed {
		bad := bytes.Clone(sealed)
		bad[i] ^= 0x01
		if _, err := kr.open("t", "row", id, bad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipped byte %d: err = %v, want ErrDecrypt", i, err)
		}
	}
	cases := map[string]func() error{
		"other row":      func() error { _, err := kr.open("t", "other", id, sealed); return err },
		"other table":    func() error { _, err := kr.open("u", "row", id, sealed); return err },
		"relabeled key":  func() error { _, err := kr.open("t", "row", "k0", sealed); return err },
		"truncated":      func() error { _, err := kr.open("t", "row", id, sealed[:10]); return err },
		"empty":          func() error { _, err := kr.open("t", "row", id, nil); return err },
		"unknown key id": func() error { _, err := kr.open("t", "row", "k9", sealed); return err },
		"plaintext row":  func() error { _, err := kr.open("t", "row", "", []byte("x")); return err },
	}
	for name, open := range cases {
		err := open()
		if err == nil {
			t.Fatalf("%s: open succeeded", name)
		}
		if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrUnknownKeyID) {
			t.Fatalf("%s: err = %v", name, err)
		}
	}
}

func TestKeyringRotation(t *testing.T) {
	k1, k2 := randomKey(t), randomKey(t)
	old := mustKeyring(t, WithEncryptionKey("k1", k1))
	id, sealed, err := old.seal("t", "row", []byte("payload"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	rotated := mustKeyring(t, WithEncryptionKey("k2", k2), WithDecryptionKey("k1", k1))
	if got, err := rotated.open("t", "row", id, sealed); err != nil || string(got) != "payload" {
		t.Fatalf("decrypt-only key: %q, %v", got, err)
	}
	newID, resealed, err := rotated.seal("t", "row", []byte("payload"))
	if err != nil || newID != "k2" {
		t.Fatalf("reseal id = %q, %v", newID, err)
	}

	retired := mustKeyring(t, WithEncryptionKey("k2", k2))
	if _, err := retired.open("t", "row", id, sealed); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("retired key: err = %v, want ErrUnknownKeyID", err)
	}
	if _, err := retired.open("t", "row", newID, resealed); err != nil {
		t.Fatalf("resealed row: %v", err)
	}
}

func TestKeyringConfigErrors(t *testing.T) {
	k := randomKey(t)
	cases := map[string]struct {
		opts []Option
		want error
	}{
		"no key":            {nil, ErrNoEncryptionKey},
		"decrypt only":      {[]Option{WithDecryptionKey("k0", k)}, ErrNoEncryptionKey},
		"short key":         {[]Option{WithEncryptionKey("k1", k[:16])}, ErrInvalidKey},
		"empty id":          {[]Option{WithEncryptionKey("", k)}, ErrInvalidKey},
		"duplicate id":      {[]Option{WithEncryptionKey("k1", k), WithDecryptionKey("k1", randomKey(t))}, ErrInvalidKey},
		"bad decryption id": {[]Option{WithEncryptionKey("k1", k), WithDecryptionKey("", k)}, ErrInvalidKey},
	}
	for name, tc := range cases {
		if _, err := newKeyring(newConfig(tc.opts)); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	if _, err := NewSessionStore(nil, WithInsecurePlaintext()); err == nil {
		t.Error("nil db accepted")
	}
}

func TestKeyringInsecurePlaintext(t *testing.T) {
	kr := mustKeyring(t, WithInsecurePlaintext())
	id, sealed, err := kr.seal("t", "row", []byte("payload"))
	if err != nil || id != "" || string(sealed) != "payload" {
		t.Fatalf("plaintext seal = %q %q %v", id, sealed, err)
	}
	if got, err := kr.open("t", "row", id, sealed); err != nil || string(got) != "payload" {
		t.Fatalf("plaintext open = %q, %v", got, err)
	}
	// With a key as well, new rows are encrypted and old plaintext rows
	// stay readable.
	both := mustKeyring(t, WithInsecurePlaintext(), WithEncryptionKey("k1", randomKey(t)))
	if id, _, err := both.seal("t", "row", []byte("x")); err != nil || id != "k1" {
		t.Fatalf("seal with key and plaintext = %q, %v", id, err)
	}
	if got, err := both.open("t", "row", "", []byte("payload")); err != nil || string(got) != "payload" {
		t.Fatalf("legacy plaintext open = %q, %v", got, err)
	}
}

func TestDecodeKey(t *testing.T) {
	k := randomKey(t)
	for _, enc := range []string{
		hex.EncodeToString(k),
		base64.StdEncoding.EncodeToString(k),
		base64.RawStdEncoding.EncodeToString(k),
		base64.URLEncoding.EncodeToString(k),
		" " + base64.RawURLEncoding.EncodeToString(k) + "\n",
	} {
		got, err := DecodeKey(enc)
		if err != nil || !bytes.Equal(got, k) {
			t.Fatalf("DecodeKey(%q) = %x, %v", enc, got, err)
		}
	}
	for _, bad := range []string{"", "short", hex.EncodeToString(k[:16]), base64.StdEncoding.EncodeToString(append(k, 1))} {
		if _, err := DecodeKey(bad); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("DecodeKey(%q) err = %v, want ErrInvalidKey", bad, err)
		}
	}
}
