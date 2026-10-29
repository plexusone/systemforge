package main

import (
	"context"
	"fmt"

	ses "github.com/plexusone/omni-aws/omnimail"
	"github.com/plexusone/omnimail"

	"github.com/plexusone/systemforge/identity/systemauth"
	"github.com/plexusone/systemforge/identity/systemauthsvc"
)

// sesMailSender builds the Amazon SES sender when the configuration's
// mail.provider is ses, and returns nil otherwise: systemauthsvc builds the
// log and smtp senders itself and keeps the AWS SDK out of the library.
// Credentials come from the AWS default credential chain (environment,
// shared configuration, or the instance or task role).
func sesMailSender(ctx context.Context, cfg *systemauthsvc.Config) (omnimail.Sender, error) {
	if cfg.Mail == nil || cfg.Mail.Provider != systemauth.MailProviderSES {
		return nil, nil
	}
	sc := ses.Config{}
	if c := cfg.Mail.SES; c != nil {
		sc.Region = c.Region
		sc.ConfigurationSetName = c.ConfigurationSet
	}
	s, err := ses.NewWithContext(ctx, sc)
	if err != nil {
		return nil, fmt.Errorf("mail.ses: %w", err)
	}
	return s, nil
}
