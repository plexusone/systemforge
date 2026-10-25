package systemauth

import (
	"errors"
	"net/netip"
	"testing"
)

func TestConnectionsConfigEgressPrefixes(t *testing.T) {
	base := ConnectionsConfig{KeysDir: "/keys", Vault: "env://", RootKey: "ROOT"}

	c := base
	c.EgressAllowPrefixes = []string{"127.0.0.1/8", "10.1.0.0/16"}
	if err := c.validate(); err != nil {
		t.Fatalf("valid prefixes refused: %v", err)
	}
	got, err := c.EgressPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("10.1.0.0/16")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("prefixes = %v, want %v", got, want)
	}

	c = base
	c.EgressAllowPrefixes = []string{"127.0.0.1"}
	if err := c.validate(); !errors.Is(err, ErrInvalidConnectionsConfig) {
		t.Fatalf("an address without a prefix length: %v", err)
	}

	if got, err := base.EgressPrefixes(); err != nil || len(got) != 0 {
		t.Fatalf("no prefixes: %v %v", got, err)
	}
}
