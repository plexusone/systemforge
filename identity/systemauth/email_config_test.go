package systemauth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func emailLoginTestConfig(email *EmailLoginConfig, mail *MailConfig) Config {
	return Config{
		Issuer:      testIssuer,
		SocialLogin: &SocialLoginConfig{Email: email},
		Mail:        mail,
	}
}

func emailLoginTestMail() *MailConfig {
	return &MailConfig{Provider: MailProviderLog, From: "Example <no-reply@example.com>"}
}

func TestEmailLoginConfigDefaults(t *testing.T) {
	cfg := emailLoginTestConfig(&EmailLoginConfig{}, emailLoginTestMail())
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	e := cfg.SocialLogin.Email
	if e.CodeLength != DefaultEmailCodeLength || e.CodeLifetime.Duration() != DefaultEmailCodeLifetime || e.MaxAttempts != DefaultEmailMaxAttempts {
		t.Fatalf("defaults = %+v, want %d digits, %s and %d attempts", e, DefaultEmailCodeLength, DefaultEmailCodeLifetime, DefaultEmailMaxAttempts)
	}
}

func TestEmailLoginConfigKeepsStatedValues(t *testing.T) {
	cfg := emailLoginTestConfig(&EmailLoginConfig{CodeLength: 8, CodeLifetime: Duration(15 * time.Minute), MaxAttempts: 3}, emailLoginTestMail())
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	e := cfg.SocialLogin.Email
	if e.CodeLength != 8 || e.CodeLifetime.Duration() != 15*time.Minute || e.MaxAttempts != 3 {
		t.Fatalf("values = %+v, want the stated ones", e)
	}
}

func TestEmailLoginConfigDisabledByDefault(t *testing.T) {
	cfg := emailLoginTestConfig(nil, nil)
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.SocialLogin.Email != nil {
		t.Fatal("email sign-in is on without a section")
	}
}

func TestEmailLoginConfigValidation(t *testing.T) {
	tests := map[string]struct {
		email *EmailLoginConfig
		mail  *MailConfig
		want  string
	}{
		"needs mail":           {&EmailLoginConfig{}, nil, "mail section"},
		"code too short":       {&EmailLoginConfig{CodeLength: 5}, emailLoginTestMail(), "code_length"},
		"code too long":        {&EmailLoginConfig{CodeLength: 11}, emailLoginTestMail(), "code_length"},
		"negative code length": {&EmailLoginConfig{CodeLength: -6}, emailLoginTestMail(), "code_length"},
		"lifetime too short":   {&EmailLoginConfig{CodeLifetime: Duration(time.Minute)}, emailLoginTestMail(), "code_lifetime"},
		"lifetime too long":    {&EmailLoginConfig{CodeLifetime: Duration(time.Hour)}, emailLoginTestMail(), "code_lifetime"},
		"too few attempts":     {&EmailLoginConfig{MaxAttempts: 2}, emailLoginTestMail(), "max_attempts"},
		"too many attempts":    {&EmailLoginConfig{MaxAttempts: 11}, emailLoginTestMail(), "max_attempts"},
		"negative attempts":    {&EmailLoginConfig{MaxAttempts: -1}, emailLoginTestMail(), "max_attempts"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := emailLoginTestConfig(tc.email, tc.mail)
			cfg.ApplyDefaults()
			err := cfg.Validate()
			if !errors.Is(err, ErrInvalidSocialLoginConfig) {
				t.Fatalf("Validate err = %v, want ErrInvalidSocialLoginConfig", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate err = %q, want it to name %q", err, tc.want)
			}
		})
	}
}

func TestEmailLoginConfigBounds(t *testing.T) {
	for name, e := range map[string]*EmailLoginConfig{
		"shortest code":     {CodeLength: MinEmailCodeLength},
		"longest code":      {CodeLength: MaxEmailCodeLength},
		"shortest lifetime": {CodeLifetime: Duration(MinEmailCodeLifetime)},
		"longest lifetime":  {CodeLifetime: Duration(MaxEmailCodeLifetime)},
		"fewest attempts":   {MaxAttempts: MinEmailMaxAttempts},
		"most attempts":     {MaxAttempts: MaxEmailMaxAttempts},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := emailLoginTestConfig(e, emailLoginTestMail())
			cfg.ApplyDefaults()
			if err := cfg.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}
