package filter

import (
	"strings"
	"testing"
)

// The parser accepts only a complete expression: trailing tokens, stray
// characters and excessive nesting are errors, not ignored.
func TestParseRejectsIncompleteOrUnboundedInput(t *testing.T) {
	for _, f := range []string{
		`userName eq "a" garbage`,
		`userName eq "a")`,
		`userName eq "a" $ or userName pr`,
		"userName eq \"a\"\x00 or userName pr",
		`emails[type eq "work"].value eq "a"`,
		strings.Repeat("(", MaxDepth+1) + `userName pr` + strings.Repeat(")", MaxDepth+1),
		strings.Repeat("not (", MaxDepth+1) + `userName pr` + strings.Repeat(")", MaxDepth+1),
	} {
		if node, err := ParseFilter(f); err == nil {
			t.Errorf("ParseFilter(%q) = %v, want an error", f, node)
		}
	}
	nested := strings.Repeat("(", MaxDepth-1) + `userName pr` + strings.Repeat(")", MaxDepth-1)
	if _, err := ParseFilter(nested); err != nil {
		t.Errorf("nesting within the limit: %v", err)
	}
}
