package systemauthsvc_test

import (
	"strings"
	"testing"

	"github.com/plexusone/omnimail/memsender"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func mailConfig(provider string) *systemauth.MailConfig {
	m := &systemauth.MailConfig{Provider: provider, From: "no-reply@example.com"}
	if provider == systemauth.MailProviderSMTP {
		m.SMTP = &systemauth.SMTPMailConfig{Host: "smtp.example.com", Username: "u", Password: "p"}
	}
	return m
}

func TestProductionRefusesLogMail(t *testing.T) {
	base := systemauthsvc.Config{
		Issuer:      "https://auth.example.com",
		Tokens:      prodTokens,
		DPoP:        prodDPoP,
		Database:    &systemauth.DatabaseConfig{Driver: "sqlite", DSN: "file::memory:"},
		SocialLogin: &systemauth.SocialLoginConfig{},
	}
	opts := systemauthsvc.Options{SigningKey: testKey(t)}

	logMail := base
	logMail.Mail = mailConfig(systemauth.MailProviderLog)
	err := systemauthsvc.CheckProduction(&logMail, opts)
	if err == nil || !strings.Contains(err.Error(), "mail.provider log") {
		t.Fatalf("log mail in production: %v", err)
	}
	// production.allow has no waiver for it.
	logMail.Production.Allow = []string{systemauth.AllowEphemeralHMACSecret, systemauth.AllowBearerTokenClients, systemauth.AllowClientSecretClientCredentials}
	if err := systemauthsvc.CheckProduction(&logMail, opts); err == nil {
		t.Fatal("a production waiver allowed the log mail sender")
	}
	if err := systemauthsvc.CheckProduction(&logMail, systemauthsvc.Options{Dev: true}); err != nil {
		t.Fatalf("log mail in development: %v", err)
	}
	smtpMail := base
	smtpMail.Mail = mailConfig(systemauth.MailProviderSMTP)
	if err := systemauthsvc.CheckProduction(&smtpMail, opts); err != nil {
		t.Fatalf("smtp mail in production: %v", err)
	}
}

func devMailConfig(m *systemauth.MailConfig) *systemauthsvc.Config {
	return &systemauthsvc.Config{
		Issuer:      "http://localhost:8080",
		SocialLogin: &systemauth.SocialLoginConfig{GitHub: &systemauth.SocialProviderConfig{ClientID: "id", ClientSecret: "secret"}, InsecureCookies: true},
		Mail:        m,
	}
}

func TestNewBuildsMailSenders(t *testing.T) {
	for _, provider := range []string{systemauth.MailProviderLog, systemauth.MailProviderSMTP} {
		s, err := systemauthsvc.New(t.Context(), devMailConfig(mailConfig(provider)), systemauthsvc.Options{Dev: true, Logger: discardLogger()})
		if err != nil {
			t.Fatalf("provider %s: %v", provider, err)
		}
		closeService(t, s)
	}

	// SES needs the deployment's sender.
	_, err := systemauthsvc.New(t.Context(), devMailConfig(mailConfig(systemauth.MailProviderSES)), systemauthsvc.Options{Dev: true, Logger: discardLogger()})
	if err == nil || !strings.Contains(err.Error(), "Options.MailSender") {
		t.Fatalf("ses without a sender: %v", err)
	}
	s, err := systemauthsvc.New(t.Context(), devMailConfig(mailConfig(systemauth.MailProviderSES)),
		systemauthsvc.Options{Dev: true, Logger: discardLogger(), MailSender: memsender.New()})
	if err != nil {
		t.Fatalf("ses with a sender: %v", err)
	}
	closeService(t, s)
}
