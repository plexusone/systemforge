package scimtoken

import (
	"regexp"
	"testing"
)

func TestTokenFormat(t *testing.T) {
	re := regexp.MustCompile(`^sfscim_[0-9A-Za-z]{49}$`)
	seen := map[string]bool{}
	for range 200 {
		tok, err := newToken()
		if err != nil {
			t.Fatal(err)
		}
		if !re.MatchString(tok) || len(tok) != Length {
			t.Fatalf("token does not match the documented format (length %d)", len(tok))
		}
		if !wellFormed(tok) {
			t.Fatal("generated token fails its own checksum")
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
		if len(displayPrefix(tok)) != DisplayLength {
			t.Fatal("display prefix length")
		}
	}
}

func TestBase62Width(t *testing.T) {
	top := make([]byte, RandomBytes)
	for i := range top {
		top[i] = 0xff
	}
	if got := base62(top, BodyLength); len(got) != BodyLength {
		t.Fatalf("largest body encodes to %d characters, want %d", len(got), BodyLength)
	}
	if got := base62([]byte{0}, BodyLength); len(got) != BodyLength {
		t.Fatalf("zero body encodes to %d characters", len(got))
	}
	if got := checksum("x"); len(got) != ChecksumLength {
		t.Fatalf("checksum length %d", len(got))
	}
}
