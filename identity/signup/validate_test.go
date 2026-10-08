package signup

import (
	"errors"
	"testing"
)

func TestValidateEmail(t *testing.T) {
	for _, ok := range []string{"kim@example.com", "a.b+c@sub.example.org"} {
		if err := validateEmail(ok); err != nil {
			t.Errorf("validateEmail(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"human:6f1c1d1e-0000-4000-8000-000000000000", // a managed principal's identifier
		"Kim <kim@example.com>",
		"not-an-email",
		" kim@example.com",
	} {
		if err := validateEmail(bad); !errors.Is(err, ErrInvalidEmail) {
			t.Errorf("validateEmail(%q) = %v, want ErrInvalidEmail", bad, err)
		}
	}
}
