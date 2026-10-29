package systemauthsvc

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/plexusone/omnimail"
	"github.com/plexusone/omnimail/logsender"
	"github.com/plexusone/omnimail/smtp"

	"github.com/plexusone/systemforge/identity/systemauth"
)

// mailOptions returns the server options delivering the configuration's
// mail: Options.MailSender when set, otherwise a log or SMTP sender built
// from mail. Provider ses needs Options.MailSender, so that this package
// stays free of vendor SDKs.
func mailOptions(c *Config, opts Options, logger *slog.Logger) ([]systemauth.Option, error) {
	if c.Mail == nil {
		if opts.MailSender != nil {
			logger.Warn("Options.MailSender is set but the configuration has no mail; no mail is sent")
		}
		return nil, nil
	}
	sender, err := buildMailSender(c.Mail, opts, logger)
	if err != nil {
		return nil, err
	}
	logger.Info("verification mail enabled", "provider", c.Mail.Provider)
	return []systemauth.Option{systemauth.WithMailSender(sender)}, nil
}

func buildMailSender(m *systemauth.MailConfig, opts Options, logger *slog.Logger) (omnimail.Sender, error) {
	if opts.MailSender != nil {
		return opts.MailSender, nil
	}
	switch m.Provider {
	case systemauth.MailProviderLog:
		// The log sender exists to show the links in development, so it
		// logs bodies; production mode refuses it.
		logger.Warn("mail.provider log: verification links are written to the log, not delivered")
		return logsender.New(logger, logsender.WithBodies()), nil
	case systemauth.MailProviderSMTP:
		return smtpSender(m.SMTP)
	case systemauth.MailProviderSES:
		return nil, errors.New("systemauthsvc: mail.provider ses needs Options.MailSender (the systemauth binary builds it from mail.ses)")
	default:
		return nil, fmt.Errorf("systemauthsvc: unknown mail.provider %q", m.Provider)
	}
}

func smtpSender(c *systemauth.SMTPMailConfig) (omnimail.Sender, error) {
	if c == nil {
		return nil, errors.New("systemauthsvc: mail.provider smtp needs mail.smtp")
	}
	security := smtp.StartTLS
	switch c.Security {
	case systemauth.SMTPSecurityTLS:
		security = smtp.ImplicitTLS
	case systemauth.SMTPSecurityNone:
		security = smtp.Plaintext
	}
	s, err := smtp.New(smtp.Config{
		Host:     c.Host,
		Port:     c.Port,
		Security: security,
		Username: c.Username,
		Password: c.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("systemauthsvc: mail.smtp: %w", err)
	}
	return s, nil
}
