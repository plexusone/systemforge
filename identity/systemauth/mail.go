package systemauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/plexusone/omnimail"
	"github.com/plexusone/omnimail/logsender"

	"github.com/plexusone/systemforge/session/ratelimit"
)

// Mail providers accepted by mail.provider.
const (
	// MailProviderSES delivers through Amazon SES. The deployment supplies
	// the sender (WithMailSender); the packaged systemauth binary builds it
	// from mail.ses.
	MailProviderSES = "ses"
	// MailProviderSMTP delivers through an SMTP server (mail.smtp).
	MailProviderSMTP = "smtp"
	// MailProviderLog writes messages, verification links included, to the
	// server log instead of delivering them. Development only: production
	// mode refuses it.
	MailProviderLog = "log"
)

var mailProviders = []string{MailProviderSES, MailProviderSMTP, MailProviderLog}

// SMTP connection security modes accepted by mail.smtp.security.
const (
	SMTPSecurityStartTLS = "starttls"
	SMTPSecurityTLS      = "tls"
	SMTPSecurityNone     = "none"
)

// Default send limits for verification mail (mail.limits).
var (
	// DefaultMailPerAddressLimit bounds the verification messages sent to
	// one address.
	DefaultMailPerAddressLimit = ratelimit.PerHour(5)
	// DefaultMailPerClientLimit bounds the verification messages one
	// client address may cause to be sent, whatever the recipient.
	DefaultMailPerClientLimit = ratelimit.PerHour(20)
)

// MailConfig configures the transactional mail SystemAuth sends to verify
// email addresses (ADR-003): the link that completes a social sign-in with
// an unverified provider email, the link that confirms an email change,
// and the notice sent to the old address. Mail needs social login, whose
// browser sessions the flows use. Without it, SystemAuth sends no mail and
// refuses sign-ins whose provider email is unverified.
//
//nolint:gosec // G117: SMTP credentials are configuration fields, read from the environment
type MailConfig struct {
	// Provider selects how mail is delivered: ses, smtp or log.
	Provider string `json:"provider" yaml:"provider" jsonschema:"required,enum=ses,enum=smtp,enum=log,description=Mail delivery provider (log is development only)"`

	// From is the sender, an address with an optional display name, e.g.
	// "Example <no-reply@example.com>". Its domain must be one the
	// provider may send for (an SES verified identity).
	From string `json:"from" yaml:"from" jsonschema:"required,description=Sender address with optional display name"`

	// ReplyTo is an optional Reply-To address, such as a support mailbox.
	ReplyTo string `json:"reply_to,omitempty" yaml:"reply_to,omitempty" jsonschema:"description=Optional Reply-To address"`

	// ProductName names the service in subjects and bodies. Default: the
	// issuer's host name.
	ProductName string `json:"product_name,omitempty" yaml:"product_name,omitempty" jsonschema:"description=Product name used in messages (default: the issuer host)"`

	// SupportURL is an optional absolute https URL messages point people
	// to for help.
	SupportURL string `json:"support_url,omitempty" yaml:"support_url,omitempty" jsonschema:"format=uri,description=Optional https URL for help, shown in messages"`

	// TokenLifetime is how long a verification link works. Default: 30m.
	TokenLifetime Duration `json:"token_lifetime,omitempty" yaml:"token_lifetime,omitempty" jsonschema:"default=30m,description=How long a verification link works (5m to 24h)"`

	// PerAddress bounds the verification messages sent to one address.
	// Default: 5 an hour.
	PerAddress *RateLimitRule `json:"per_address,omitempty" yaml:"per_address,omitempty" jsonschema:"description=Limit on messages sent to one address (default 5 per hour)"`

	// PerClient bounds the verification messages one client address may
	// cause to be sent. Default: 20 an hour.
	PerClient *RateLimitRule `json:"per_client,omitempty" yaml:"per_client,omitempty" jsonschema:"description=Limit on messages one client address may cause (default 20 per hour)"`

	// SMTP configures the smtp provider.
	SMTP *SMTPMailConfig `json:"smtp,omitempty" yaml:"smtp,omitempty" jsonschema:"description=SMTP server (provider smtp)"`

	// SES configures the ses provider for the packaged systemauth binary.
	// An embedding application builds its own sender and passes it with
	// WithMailSender.
	SES *SESMailConfig `json:"ses,omitempty" yaml:"ses,omitempty" jsonschema:"description=Amazon SES settings (provider ses)"`
}

// SMTPMailConfig is an SMTP server.
//
//nolint:gosec // G117: SMTP credentials are configuration fields, read from the environment
type SMTPMailConfig struct {
	// Host is the server host name.
	Host string `json:"host" yaml:"host" jsonschema:"required,description=SMTP server host name"`
	// Port defaults to 587 (starttls), 465 (tls) or 25 (none).
	Port int `json:"port,omitempty" yaml:"port,omitempty" jsonschema:"minimum=1,maximum=65535,description=SMTP port (default by security mode)"`
	// Security is starttls (the default), tls or none. Credentials are
	// never sent over a connection without TLS.
	Security string `json:"security,omitempty" yaml:"security,omitempty" jsonschema:"enum=starttls,enum=tls,enum=none,default=starttls,description=Connection security"`
	// Username enables SMTP AUTH. Supports environment variable
	// expansion: ${SYSTEMAUTH_SMTP_USERNAME}.
	Username string `json:"username,omitempty" yaml:"username,omitempty" jsonschema:"description=SMTP AUTH username (supports env var expansion)"`
	// Password is the SMTP AUTH password. Keep it out of the file:
	// ${SYSTEMAUTH_SMTP_PASSWORD}.
	Password string `json:"password,omitempty" yaml:"password,omitempty" jsonschema:"description=SMTP AUTH password (use env var expansion)"`
}

// SESMailConfig holds the Amazon SES settings the packaged binary uses.
// Credentials come from the AWS default credential chain.
type SESMailConfig struct {
	// Region is the AWS region of the SES identity. Default: the region
	// from the environment or shared configuration.
	Region string `json:"region,omitempty" yaml:"region,omitempty" jsonschema:"description=AWS region of the SES identity"`
	// ConfigurationSet is the SES configuration set applied to every
	// message, for event publishing (bounces, complaints).
	ConfigurationSet string `json:"configuration_set,omitempty" yaml:"configuration_set,omitempty" jsonschema:"description=SES configuration set for event publishing"`
}

// Bounds of mail.token_lifetime.
const (
	minVerificationTokenTTL = 5 * time.Minute
	maxVerificationTokenTTL = 24 * time.Hour
)

func (c *MailConfig) applyDefaults(issuer string) {
	if c.TokenLifetime == 0 {
		c.TokenLifetime = Duration(DefaultVerificationTokenTTL)
	}
	if c.ProductName == "" {
		if u, err := url.Parse(issuer); err == nil && u.Hostname() != "" {
			c.ProductName = u.Hostname()
		}
	}
	if c.SMTP != nil && c.SMTP.Security == "" {
		c.SMTP.Security = SMTPSecurityStartTLS
	}
}

func (c *MailConfig) validate() error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: mail: %s", ErrInvalidConfig, fmt.Sprintf(format, args...))
	}
	if !slices.Contains(mailProviders, c.Provider) {
		return invalid("provider must be one of %s", strings.Join(mailProviders, ", "))
	}
	if _, err := omnimail.ParseAddress(c.From); err != nil {
		return invalid("from: %v", err)
	}
	if c.ReplyTo != "" {
		if _, err := omnimail.ParseAddress(c.ReplyTo); err != nil {
			return invalid("reply_to: %v", err)
		}
	}
	if c.SupportURL != "" {
		u, err := url.Parse(c.SupportURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return invalid("support_url must be an absolute https URL")
		}
	}
	if d := c.TokenLifetime.Duration(); d != 0 && (d < minVerificationTokenTTL || d > maxVerificationTokenTTL) {
		return invalid("token_lifetime must be between %s and %s", minVerificationTokenTTL, maxVerificationTokenTTL)
	}
	if err := c.PerAddress.validate("mail.per_address"); err != nil {
		return err
	}
	if err := c.PerClient.validate("mail.per_client"); err != nil {
		return err
	}
	if c.Provider == MailProviderSMTP {
		if c.SMTP == nil || c.SMTP.Host == "" {
			return invalid("provider smtp needs smtp.host")
		}
	}
	if s := c.SMTP; s != nil {
		if s.Port < 0 || s.Port > 65535 {
			return invalid("smtp.port must be between 1 and 65535")
		}
		if s.Security != "" && !slices.Contains([]string{SMTPSecurityStartTLS, SMTPSecurityTLS, SMTPSecurityNone}, s.Security) {
			return invalid("smtp.security must be starttls, tls or none")
		}
	}
	return nil
}

// WithMailSender sets the sender of SystemAuth's mail. It is required when
// the configuration has mail; mail.provider documents which sender the
// deployment chose. The packaged service (systemauthsvc) builds the log
// and smtp senders and takes ses from its options.
func WithMailSender(sender omnimail.Sender) Option {
	return func(s *Server) { s.mailSender = sender }
}

// WithVerificationTokenStore sets the store of email verification tokens.
// Defaults to an EntVerificationTokenStore when the server uses
// EntStorage, otherwise an in-memory (single-instance) store.
func WithVerificationTokenStore(store VerificationTokenStore) Option {
	return func(s *Server) { s.verificationTokens = store }
}

// mailKind names a message SystemAuth sends.
type mailKind string

const (
	// mailVerifySignIn carries the link completing a pending sign-in.
	mailVerifySignIn mailKind = "verify_sign_in"
	// mailVerifyChange carries the link confirming a new address.
	mailVerifyChange mailKind = "verify_email_change"
	// mailChangeRequested tells the old address a change was asked for.
	mailChangeRequested mailKind = "email_change_requested"
	// mailChanged tells the old address the change was made.
	mailChanged mailKind = "email_changed"
)

// mailData is what the templates see.
type mailData struct {
	Product    string
	SupportURL string
	// Link is the verification link (verification messages only).
	Link string
	// ExpiresIn says how long Link works, e.g. "30 minutes".
	ExpiresIn string
	// NewEmail is the requested address, masked (notices only).
	NewEmail string
	// AccountURL is the page where the person manages their email.
	AccountURL string
}

// mailTemplates are the built-in, branded messages. Subjects and text
// bodies are plain text; HTML bodies are html/template, so every value is
// escaped for its context.
var mailTemplates = map[mailKind]omnimail.TemplateSource{
	mailVerifySignIn: {
		Subject: `Verify your email address for {{.Product}}`,
		Text: `Confirm this email address to finish signing in to {{.Product}}:

{{.Link}}

Open the link in the same browser you used to sign in. It works once and expires in {{.ExpiresIn}}.

If you did not try to sign in to {{.Product}}, ignore this message: nothing happens unless the link is used.
{{if .SupportURL}}
Help: {{.SupportURL}}
{{end}}`,
		HTML: `<!doctype html>
<html lang="en"><body style="font-family:sans-serif;line-height:1.5">
<p>Confirm this email address to finish signing in to <strong>{{.Product}}</strong>.</p>
<p><a href="{{.Link}}">Verify email address</a></p>
<p>Open the link in the same browser you used to sign in. It works once and expires in {{.ExpiresIn}}.</p>
<p>If you did not try to sign in to {{.Product}}, ignore this message: nothing happens unless the link is used.</p>
{{if .SupportURL}}<p><a href="{{.SupportURL}}">Help</a></p>{{end}}
</body></html>`,
	},
	mailVerifyChange: {
		Subject: `Confirm your new email address for {{.Product}}`,
		Text: `Someone signed in to {{.Product}} asked to use this address for their account. To confirm, open:

{{.Link}}

The link works once, while you are signed in, and expires in {{.ExpiresIn}}.

If you did not ask for this, ignore this message: the address is not used unless the link is opened.
{{if .SupportURL}}
Help: {{.SupportURL}}
{{end}}`,
		HTML: `<!doctype html>
<html lang="en"><body style="font-family:sans-serif;line-height:1.5">
<p>Someone signed in to <strong>{{.Product}}</strong> asked to use this address for their account.</p>
<p><a href="{{.Link}}">Confirm new email address</a></p>
<p>The link works once, while you are signed in, and expires in {{.ExpiresIn}}.</p>
<p>If you did not ask for this, ignore this message: the address is not used unless the link is opened.</p>
{{if .SupportURL}}<p><a href="{{.SupportURL}}">Help</a></p>{{end}}
</body></html>`,
	},
	mailChangeRequested: {
		Subject: `Your {{.Product}} email address may change`,
		Text: `Someone signed in to your {{.Product}} account asked to change its email address to {{.NewEmail}}. Nothing changes until the new address is confirmed.

If this was not you, sign in and cancel the change, then review your account:

{{.AccountURL}}
{{if .SupportURL}}
Help: {{.SupportURL}}
{{end}}`,
		HTML: `<!doctype html>
<html lang="en"><body style="font-family:sans-serif;line-height:1.5">
<p>Someone signed in to your <strong>{{.Product}}</strong> account asked to change its email address to {{.NewEmail}}. Nothing changes until the new address is confirmed.</p>
<p>If this was not you, <a href="{{.AccountURL}}">sign in and cancel the change</a>, then review your account.</p>
{{if .SupportURL}}<p><a href="{{.SupportURL}}">Help</a></p>{{end}}
</body></html>`,
	},
	mailChanged: {
		Subject: `Your {{.Product}} email address was changed`,
		Text: `The email address of your {{.Product}} account was changed to {{.NewEmail}}. This address no longer receives its messages.

If this was not you, contact support at once.
{{if .SupportURL}}
Help: {{.SupportURL}}
{{end}}`,
		HTML: `<!doctype html>
<html lang="en"><body style="font-family:sans-serif;line-height:1.5">
<p>The email address of your <strong>{{.Product}}</strong> account was changed to {{.NewEmail}}. This address no longer receives its messages.</p>
<p>If this was not you, contact support at once.</p>
{{if .SupportURL}}<p><a href="{{.SupportURL}}">Help</a></p>{{end}}
</body></html>`,
	},
}

// mailer sends SystemAuth's mail within its send limits.
type mailer struct {
	sender     omnimail.Sender
	from       omnimail.Address
	replyTo    []omnimail.Address
	product    string
	supportURL string
	issuer     string
	ttl        time.Duration
	templates  map[mailKind]*omnimail.Template

	rates      ratelimit.Storage
	perAddress ratelimit.Limit
	perClient  ratelimit.Limit
	clientIP   func(*http.Request) string
}

// newMailer builds the mailer for cfg, or nil when mail is not configured.
func newMailer(s *Server) (*mailer, error) {
	cfg := s.config.Mail
	if cfg == nil {
		return nil, nil
	}
	if s.mailSender == nil {
		return nil, fmt.Errorf("%w: mail is configured (provider %s) but no sender was supplied (WithMailSender)", ErrInvalidConfig, cfg.Provider)
	}
	if s.production.RefuseLogMailSender {
		if _, isLog := s.mailSender.(*logsender.Sender); isLog || cfg.Provider == MailProviderLog {
			return nil, fmt.Errorf("%w: the log mail sender writes verification links to the log and is not allowed in production", ErrInvalidConfig)
		}
	}
	from, err := omnimail.ParseAddress(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("%w: mail.from: %v", ErrInvalidConfig, err)
	}
	m := &mailer{
		sender:     s.mailSender,
		from:       from,
		product:    cfg.ProductName,
		supportURL: cfg.SupportURL,
		issuer:     strings.TrimRight(s.config.Issuer, "/"),
		ttl:        cfg.TokenLifetime.Duration(),
		templates:  map[mailKind]*omnimail.Template{},
		rates:      s.rates,
		perAddress: DefaultMailPerAddressLimit,
		perClient:  DefaultMailPerClientLimit,
		clientIP:   s.clientIP,
	}
	if m.ttl <= 0 {
		m.ttl = DefaultVerificationTokenTTL
	}
	if m.product == "" {
		m.product = "SystemAuth"
	}
	if cfg.ReplyTo != "" {
		rt, err := omnimail.ParseAddress(cfg.ReplyTo)
		if err != nil {
			return nil, fmt.Errorf("%w: mail.reply_to: %v", ErrInvalidConfig, err)
		}
		m.replyTo = []omnimail.Address{rt}
	}
	if cfg.PerAddress != nil {
		m.perAddress = cfg.PerAddress.limit()
	}
	if cfg.PerClient != nil {
		m.perClient = cfg.PerClient.limit()
	}
	for kind, src := range mailTemplates {
		t, err := omnimail.ParseTemplate(string(kind), src)
		if err != nil {
			return nil, fmt.Errorf("parsing mail template %s: %w", kind, err)
		}
		m.templates[kind] = t
	}
	return m, nil
}

// sendDecision is what the send limits allow.
type sendDecision int

const (
	// sendAllowed: send the message.
	sendAllowed sendDecision = iota
	// sendSuppressed: the recipient's limit is used up. Answer as if the
	// message was sent, so the response does not depend on the address.
	sendSuppressed
	// sendRefused: the client's limit is used up; it has been answered
	// with 429.
	sendRefused
	// sendFailed: the limit storage failed; it has been answered with 503.
	sendFailed
)

// allowSend counts a send to email against the per-client and per-address
// limits. The per-client limit answers the request when it is used up; the
// per-address limit only suppresses the message, so a response never says
// whether an address was already sent mail.
func (m *mailer) allowSend(w http.ResponseWriter, r *http.Request, email string) sendDecision {
	ctx := r.Context()
	logger := LoggerFromContext(ctx)
	address := m.clientIP(r)
	if address == "" {
		address = "unknown"
	}
	if ratelimit.Check(w, r, m.rates, "mail_per_client", "ip:"+address, m.perClient, false, logger) != ratelimit.Allowed {
		return sendRefused
	}
	res, err := ratelimit.Record(ctx, m.rates, "mail_per_address", "email:"+hashSessionToken(strings.ToLower(email)), m.perAddress)
	if err != nil && !errors.Is(err, ratelimit.ErrTooManyKeys) {
		logger.Error("rate limit storage failed", "policy", "mail_per_address", "error", err)
		http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
		return sendFailed
	}
	if err != nil || !res.Allowed {
		logger.Info("verification mail suppressed: the address's send limit is used up")
		return sendSuppressed
	}
	return sendAllowed
}

// send renders kind for data and delivers it to to. Delivery failures are
// returned; callers log them and answer as if the message was sent.
func (m *mailer) send(ctx context.Context, kind mailKind, to string, data mailData) error {
	addr, err := omnimail.ParseAddress(to)
	if err != nil {
		return err
	}
	data.Product = m.product
	data.SupportURL = m.supportURL
	data.ExpiresIn = humanDuration(m.ttl)
	msg := &omnimail.Message{
		From:    m.from,
		To:      []omnimail.Address{addr},
		ReplyTo: m.replyTo,
		Tags:    map[string]string{"systemauth": string(kind)},
	}
	if err := m.templates[kind].Apply(msg, data); err != nil {
		return err
	}
	if _, err := m.sender.Send(ctx, msg); err != nil {
		return fmt.Errorf("sending %s mail: %w", kind, err)
	}
	return nil
}

// link returns the absolute URL of path on the issuer with token in its
// query.
func (m *mailer) link(path, token string) string {
	return m.issuer + path + "?" + url.Values{"token": {token}}.Encode()
}

// humanDuration says d in minutes or hours for a message.
func humanDuration(d time.Duration) string {
	switch {
	case d >= time.Hour && d%time.Hour == 0:
		if d == time.Hour {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", d/time.Hour)
	case d <= time.Minute:
		return "1 minute"
	default:
		return fmt.Sprintf("%d minutes", (d+time.Minute-1)/time.Minute)
	}
}

// maskEmail hides most of an address's local part, for notices sent to
// another address: "jane@example.com" becomes "j***@example.com".
func maskEmail(email string) string {
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return "***"
	}
	_, size := utf8.DecodeRuneInString(email)
	return email[:size] + "***" + email[at:]
}

// setupMail builds the mailer and the verification token store when the
// configuration has mail.
func (s *Server) setupMail() error {
	m, err := newMailer(s)
	if err != nil || m == nil {
		return err
	}
	s.mail = m
	if s.verificationTokens == nil {
		if es, ok := s.storage.(*EntStorage); ok {
			s.verificationTokens = NewEntVerificationTokenStore(es.db)
		} else {
			s.logger.Warn("verification tokens kept in memory; links stop working on restart and on other instances")
			s.verificationTokens = NewMemoryVerificationTokenStore()
		}
	}
	return nil
}
