package displayname_test

import (
	"testing"

	"github.com/plexusone/systemforge/identity/displayname"
)

func TestSafe(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "",
		"   ":               "",
		"Jane Doe":          "Jane Doe",
		"  Jane  Doe  ":     "Jane  Doe",
		"jane@example.com":  "",
		" jane@example.com": "",
		"Jane @ Acme":       "",
		"octocat":           "octocat",
		"Zoë Müller":        "Zoë Müller",
	} {
		if got := displayname.Safe(in); got != want {
			t.Errorf("Safe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOrAndShow(t *testing.T) {
	if got := displayname.Or("jane@example.com", "Learner"); got != "Learner" {
		t.Errorf("Or with an address = %q, want the fallback", got)
	}
	if got := displayname.Or("Jane", "Learner"); got != "Jane" {
		t.Errorf("Or with a name = %q, want the name", got)
	}
	if got := displayname.Or("", ""); got != "" {
		t.Errorf("Or with neither = %q, want the empty fallback", got)
	}
	for _, in := range []string{"", "a@b.co", "  "} {
		if got := displayname.Show(in); got != displayname.Default {
			t.Errorf("Show(%q) = %q, want %q", in, got, displayname.Default)
		}
	}
	if got := displayname.Show("Jane Doe"); got != "Jane Doe" {
		t.Errorf("Show(a name) = %q", got)
	}
}

func TestLooksLikeAddress(t *testing.T) {
	if !displayname.LooksLikeAddress("a@b.co") || displayname.LooksLikeAddress("Jane Doe") {
		t.Fatal("LooksLikeAddress is wrong")
	}
}
