package main

import (
	"testing"

	ses "github.com/plexusone/omni-aws/omnimail"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

func TestSESMailSender(t *testing.T) {
	for _, cfg := range []*systemauthsvc.Config{
		{},
		{Mail: &systemauth.MailConfig{Provider: systemauth.MailProviderSMTP}},
	} {
		s, err := sesMailSender(t.Context(), cfg)
		if err != nil || s != nil {
			t.Fatalf("non-SES configuration: sender %v, err %v; want neither", s, err)
		}
	}

	// Building the sender loads AWS configuration but does not contact SES.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "example-secret")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/none")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/none")
	s, err := sesMailSender(t.Context(), &systemauthsvc.Config{Mail: &systemauth.MailConfig{
		Provider: systemauth.MailProviderSES,
		SES:      &systemauth.SESMailConfig{Region: "us-east-1", ConfigurationSet: "transactional"},
	}})
	if err != nil {
		t.Fatalf("sesMailSender: %v", err)
	}
	if _, ok := s.(*ses.Sender); !ok {
		t.Fatalf("sender is %T, want *ses.Sender", s)
	}
}
