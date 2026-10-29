package systemauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/plexusone/omnimail/logsender"
	"github.com/plexusone/omnimail/memsender"
)

func testMailConfig() *MailConfig {
	return &MailConfig{Provider: MailProviderSMTP, From: "Example <no-reply@example.com>", SMTP: &SMTPMailConfig{Host: "smtp.example.com"}}
}

func mailServerConfig(m *MailConfig) Config {
	return Config{Issuer: testIssuer, SocialLogin: &SocialLoginConfig{}, Mail: m}
}

func TestMailConfigValidation(t *testing.T) {
	valid := func() *MailConfig { return testMailConfig() }
	cases := map[string]func(*MailConfig){
		"unknown provider":   func(m *MailConfig) { m.Provider = "pigeon" },
		"no from":            func(m *MailConfig) { m.From = "" },
		"bad from":           func(m *MailConfig) { m.From = "not an address" },
		"bad reply_to":       func(m *MailConfig) { m.ReplyTo = "nope" },
		"http support url":   func(m *MailConfig) { m.SupportURL = "http://help.example.com" },
		"short lifetime":     func(m *MailConfig) { m.TokenLifetime = Duration(time.Minute) },
		"long lifetime":      func(m *MailConfig) { m.TokenLifetime = Duration(48 * time.Hour) },
		"smtp without host":  func(m *MailConfig) { m.SMTP = nil },
		"bad smtp security":  func(m *MailConfig) { m.SMTP.Security = "ssl3" },
		"bad smtp port":      func(m *MailConfig) { m.SMTP.Port = 70000 },
		"zero per address":   func(m *MailConfig) { m.PerAddress = &RateLimitRule{} },
		"zero per client":    func(m *MailConfig) { m.PerClient = &RateLimitRule{Requests: 1} },
		"negative smtp port": func(m *MailConfig) { m.SMTP.Port = -1 },
	}
	for name, mutate := range cases {
		m := valid()
		mutate(m)
		cfg := mailServerConfig(m)
		cfg.ApplyDefaults()
		if err := cfg.Validate(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: Validate = %v, want ErrInvalidConfig", name, err)
		}
	}

	cfg := mailServerConfig(valid())
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	if cfg.Mail.TokenLifetime.Duration() != DefaultVerificationTokenTTL || cfg.Mail.ProductName != "auth.example.com" ||
		cfg.Mail.SMTP.Security != SMTPSecurityStartTLS {
		t.Errorf("defaults not applied: %+v", cfg.Mail)
	}

	noSocial := Config{Issuer: testIssuer, Mail: valid()}
	noSocial.ApplyDefaults()
	if err := noSocial.Validate(); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("mail without social login: Validate = %v, want ErrInvalidConfig", err)
	}
}

func TestParseConfigMailSecretsFromEnv(t *testing.T) {
	t.Setenv("TEST_SMTP_USER", "mailer")
	t.Setenv("TEST_SMTP_PASSWORD", "pa$$word")
	cfg, err := ParseConfig([]byte(`
issuer: https://auth.example.com
social_login: {}
mail:
  provider: smtp
  from: no-reply@example.com
  smtp:
    host: smtp.example.com
    username: ${TEST_SMTP_USER}
    password: ${TEST_SMTP_PASSWORD}
`), FormatYAML)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Mail.SMTP.Username != "mailer" || cfg.Mail.SMTP.Password != "pa$$word" {
		t.Errorf("SMTP credentials not expanded: %q %q", cfg.Mail.SMTP.Username, cfg.Mail.SMTP.Password)
	}
}

func TestNewEmbeddedMailNeedsSender(t *testing.T) {
	if _, err := NewEmbedded(mailServerConfig(testMailConfig()), WithSocialConnector(newFakeGitHub(t).connector())); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewEmbedded without a sender = %v, want ErrInvalidConfig", err)
	}
}

func TestNewEmbeddedProductionRefusesLogSender(t *testing.T) {
	f := newFakeGitHub(t)
	logCfg := testMailConfig()
	logCfg.Provider = MailProviderLog
	for name, tc := range map[string]struct {
		cfg *MailConfig
		opt Option
	}{
		"log provider":    {logCfg, WithMailSender(memsender.New())},
		"log sender type": {testMailConfig(), WithMailSender(logsender.New(nil))},
	} {
		_, err := NewEmbedded(mailServerConfig(tc.cfg), WithSocialConnector(f.connector()), tc.opt,
			WithProductionPolicy(ProductionPolicy{RefuseLogMailSender: true}))
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: NewEmbedded = %v, want ErrInvalidConfig", name, err)
		}
	}
	if _, err := NewEmbedded(mailServerConfig(logCfg), WithSocialConnector(f.connector()), WithMailSender(logsender.New(nil))); err != nil {
		t.Fatalf("log sender outside production: %v", err)
	}
}

func newTestMailer(t *testing.T, m *MailConfig) (*Server, *memsender.Sender) {
	t.Helper()
	sender := memsender.New()
	s, err := NewEmbedded(mailServerConfig(m), WithSocialConnector(newFakeGitHub(t).connector()), WithMailSender(sender))
	if err != nil {
		t.Fatalf("NewEmbedded: %v", err)
	}
	if s.mail == nil || s.verificationTokens == nil {
		t.Fatal("mailer or verification token store not set up")
	}
	return s, sender
}

func TestMailerRendersBrandedMessages(t *testing.T) {
	m := testMailConfig()
	m.ProductName = `Acme <Cloud> & Co`
	m.SupportURL = "https://help.example.com/mail"
	m.ReplyTo = "support@example.com"
	s, sender := newTestMailer(t, m)

	link := s.mail.link("/login/verify-email/confirm", "tok_123")
	if err := s.mail.send(context.Background(), mailVerifySignIn, "jane@example.com", mailData{Link: link}); err != nil {
		t.Fatalf("send: %v", err)
	}
	msg := sender.Last()
	if msg.To[0].Email != "jane@example.com" || msg.From.Email != "no-reply@example.com" || msg.ReplyTo[0].Email != "support@example.com" {
		t.Errorf("addressing = from %v to %v reply-to %v", msg.From, msg.To, msg.ReplyTo)
	}
	if msg.Subject != "Verify your email address for Acme <Cloud> & Co" {
		t.Errorf("subject = %q", msg.Subject)
	}
	if !strings.Contains(msg.Text, testIssuer+"/login/verify-email/confirm?token=tok_123") || !strings.Contains(msg.Text, "30 minutes") ||
		!strings.Contains(msg.Text, "https://help.example.com/mail") {
		t.Errorf("text body missing link, expiry or help: %s", msg.Text)
	}
	if !strings.Contains(msg.HTML, "Acme &lt;Cloud&gt; &amp; Co") || strings.Contains(msg.HTML, "<Cloud>") {
		t.Errorf("HTML body does not escape the product name: %s", msg.HTML)
	}
	if msg.Tags["systemauth"] != string(mailVerifySignIn) {
		t.Errorf("tags = %v", msg.Tags)
	}

	for _, kind := range []mailKind{mailVerifyChange, mailChangeRequested, mailChanged} {
		if err := s.mail.send(context.Background(), kind, "old@example.com", mailData{Link: link, NewEmail: maskEmail("new@example.com"), AccountURL: testIssuer + "/account/email"}); err != nil {
			t.Fatalf("send %s: %v", kind, err)
		}
		if strings.Contains(sender.Last().Text, "new@example.com") {
			t.Errorf("%s reveals the full new address: %s", kind, sender.Last().Text)
		}
	}
}

func TestMailerSendLimits(t *testing.T) {
	m := testMailConfig()
	m.PerAddress = &RateLimitRule{Requests: 2, Period: Duration(time.Hour)}
	m.PerClient = &RateLimitRule{Requests: 3, Period: Duration(time.Hour)}
	s, _ := newTestMailer(t, m)

	decide := func(addr string) (sendDecision, int) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		return s.mail.allowSend(w, r, addr), w.Code
	}
	for i := range 2 {
		if d, _ := decide("a@example.com"); d != sendAllowed {
			t.Fatalf("send %d to a: %v, want allowed", i, d)
		}
	}
	// The address's limit only suppresses the message: the caller answers
	// as if it were sent.
	if d, code := decide("A@example.com"); d != sendSuppressed || code != http.StatusOK {
		t.Fatalf("third send to a: %v (status %d), want suppressed without a response", d, code)
	}
	// The client's limit is answered with 429.
	if d, code := decide("b@example.com"); d != sendRefused || code != http.StatusTooManyRequests {
		t.Fatalf("fourth send from the client: %v (status %d), want refused with 429", d, code)
	}
}

func TestMaskEmailAndHumanDuration(t *testing.T) {
	for in, want := range map[string]string{
		"jane@example.com": "j***@example.com",
		"élan@example.com": "é***@example.com",
		"@example.com":     "***",
		"nope":             "***",
	} {
		if got := maskEmail(in); got != want {
			t.Errorf("maskEmail(%q) = %q, want %q", in, got, want)
		}
	}
	for d, want := range map[time.Duration]string{
		30 * time.Minute: "30 minutes",
		time.Hour:        "1 hour",
		2 * time.Hour:    "2 hours",
		90 * time.Second: "2 minutes",
		time.Second:      "1 minute",
	} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}
