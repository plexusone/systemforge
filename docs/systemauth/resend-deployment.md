# Sending Mail with Resend

SystemAuth sends [verification mail](verified-email.md) and
[sign-in codes](email-sign-in.md) through the vendor-free
[omnimail](https://github.com/plexusone/omnimail) `Sender` interface, so the
provider is configuration. [Resend](https://resend.com) offers SMTP, which
omnimail's SMTP sender speaks, so a deployment can send with Resend today and
move to [Amazon SES](ses-deployment.md) or another provider later by changing
`mail` and nothing else. No Resend-specific code is involved.

The facts below are from Resend's documentation as read when this page was
written; check them against the dashboard before relying on them.

## Configuration

```yaml
mail:
  provider: smtp
  from: "Example <no-reply@mail.example.com>"
  product_name: Example
  smtp:
    host: smtp.resend.com
    port: 465
    security: tls            # implicit TLS
    username: resend
    password: ${SYSTEMAUTH_SMTP_PASSWORD}   # a Resend API key
```

| Setting | Value |
|---------|-------|
| Host | `smtp.resend.com` |
| Ports | 465 and 2465 connect with implicit TLS (`security: tls`); 587, 2587 and 25 upgrade with STARTTLS (`security: starttls`) |
| Username | `resend` |
| Password | a Resend API key, passed in the environment, never written in the file |

Give this service its own API key, so it can be rotated alone, and keep it
out of the repository. SystemAuth sends credentials only over TLS.
Resend's pages do not state which SMTP AUTH mechanisms it accepts; omnimail
negotiates PLAIN or LOGIN with what the server offers, and the delivery check
below confirms it works.

## Domain

In the Resend dashboard, add the sending domain and publish the DNS records it
shows (DKIM and SPF, as `TXT` with `MX` or `CNAME`; the exact names and values
come from the dashboard and must match exactly). Then:

- **Use a subdomain** dedicated to this mail, such as `mail.example.com`, as
  Resend recommends, and send from an address at it (`mail.from`). Its
  reputation and DMARC policy then stay apart from the parent domain's.
- **Do not proxy** the CNAME records (turn off Cloudflare's orange cloud for
  them).
- **Add a DMARC record** after the domain verifies. Start with `p=none` and a
  reporting address, then tighten once reports are clean.
- Verification usually takes minutes and can take up to 72 hours.

Resend's documentation states no manual review before a verified domain can
send to other people. It states that a domain must be verified before sending.

## Limits to plan for

- **The free plan allows 100 messages a day and 3,000 a month** (the day
  resets at midnight UTC). Every sign-in code and verification message is one,
  and several applications launching together share the account's quota. Paid
  transactional plans have no daily limit and a monthly quota set by the plan.
  Choose the plan from the number of sign-ins you expect, not from the
  application count.
- **10 requests a second** per team, the same for SMTP as for the API.
- **Bounces under 4% and spam complaints under 0.08%** are the rates Resend
  asks accounts to stay below. Sending codes only to addresses people typed
  themselves, with the send limits in [`mail`](email-sign-in.md#configuration),
  keeps both low.
- Resend documents webhook events for delivered, bounced, complained and
  suppressed messages. SystemAuth does not consume them; watch bounces and
  complaints at Resend.

## Delivery check

Before launch, from the production deployment and the production domain:

1. Start SystemAuth with the `mail` section above and `social_login.email: {}`.
2. Request a code for an address you control at a mailbox provider you use
   (Gmail, Outlook or similar) and for a second at another provider.
3. Confirm the message arrives in the inbox, not spam, and open its headers:
   SPF, DKIM and DMARC should all show **pass** and align with the `From`
   domain.
4. Enter the code and confirm the sign-in completes.
5. Check `systemauth.email_code.sent` events show `sent: true`, and that no
   `sent: false` appears for these requests. The packaged `systemauth` command
   logs security events; an application embedding SystemAuth discards them
   unless it sets an audit emitter (`systemauth.WithAuditEmitter`, or
   `systemauthsvc.Options.AuditEmitter`), so configure one first. See the
   [security events](../security/security-events.md) reference.
6. Confirm the account's quota in the Resend dashboard moved by the number of
   messages sent.

If SMTP authentication fails, the log shows a mail error and the person sees
the same page as for a sent message; check `sent: false` events and the
server log first.
