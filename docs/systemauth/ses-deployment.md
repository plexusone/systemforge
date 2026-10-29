# Sending Mail with Amazon SES

SystemAuth's [verification mail](verified-email.md) goes out through Amazon
SES (v2 API) when `mail.provider` is `ses`. The `systemauth` binary builds the
sender with [omni-aws](https://github.com/plexusone/omni-aws)'s `omnimail`
package; an application embedding SystemAuth builds it the same way and
passes it as `systemauthsvc.Options.MailSender` or
`systemauth.WithMailSender`. This page sets up the sending domain so that
messages are authenticated and delivered.

```yaml
mail:
  provider: ses
  from: "Example <no-reply@mail.example.com>"
  product_name: Example
  ses:
    region: us-east-1
    configuration_set: systemauth-transactional
```

The examples use `mail.example.com` as the sending domain. A subdomain
dedicated to transactional mail keeps its reputation and DMARC policy apart
from people's mail at the parent domain.

## 1. Verify the domain identity

In the SES console (or `aws sesv2 create-email-identity --email-identity
mail.example.com`), create a **domain** identity for the sending domain in the
region SystemAuth uses. Verifying the domain lets any address at it be the
`From` address; `mail.from` must be at a verified identity.

## 2. DKIM

Use **Easy DKIM** (RSA 2048). SES gives three CNAME records:

```text
<token1>._domainkey.mail.example.com  CNAME  <token1>.dkim.amazonses.com
<token2>._domainkey.mail.example.com  CNAME  <token2>.dkim.amazonses.com
<token3>._domainkey.mail.example.com  CNAME  <token3>.dkim.amazonses.com
```

Publish them in DNS. The identity is verified once SES finds them, and every
message is then signed with `d=mail.example.com`, which DMARC alignment
needs.

## 3. SPF with a custom MAIL FROM domain

By default the envelope sender (`Return-Path`) is at `amazonses.com`, so SPF
passes for Amazon's domain and does not align with yours. Configure a
**custom MAIL FROM domain** on the identity, such as `bounce.mail.example.com`,
and publish:

```text
bounce.mail.example.com  MX   10 feedback-smtp.us-east-1.amazonses.com
bounce.mail.example.com  TXT  "v=spf1 include:amazonses.com -all"
```

Use the region of the identity in the MX host. Set the behavior on MX
failure to **reject message**, so nothing is sent unaligned while DNS is
wrong.

## 4. DMARC

Publish a DMARC policy for the sending domain:

```text
_dmarc.mail.example.com  TXT  "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com; adkim=s; aspf=r"
```

Start with `p=none` and read the aggregate reports. Once every legitimate
source passes DKIM or aligned SPF, move to `p=quarantine` and then
`p=reject`. Strict DKIM alignment (`adkim=s`) holds because SES signs with the
sending domain itself.

## 5. Configuration set and events

Create the configuration set named in `mail.ses.configuration_set` and add
event destinations for at least **bounces**, **complaints** and **rejects**
(Amazon SNS, EventBridge or CloudWatch). Each message carries the message tag
`systemauth` naming its kind (`verify_sign_in`, `verify_email_change`,
`email_change_requested`, `email_changed`), so dashboards and alarms can tell
them apart.

- Keep the account-level **suppression list** on for bounces and complaints:
  SES then drops sends to addresses that hard-bounced or complained, which
  protects the sending reputation. A suppressed send looks the same to the
  person as any other, by design.
- Alarm on the account's bounce and complaint rates: SES reviews an account
  whose bounce rate passes 5% or complaint rate 0.1%.

## 6. Leave the sandbox

New SES accounts are in the **sandbox**: they send only to verified
addresses, at a low rate. Request production access for the region before
launch, describing the mail as transactional verification messages sent on
request.

## 7. Credentials and permissions

The binary loads AWS credentials from the default chain: environment
variables, the shared configuration (`AWS_PROFILE`), or the instance or task
role, which is preferred. Grant only sending, from the one domain, through
the one configuration set:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ses:SendEmail", "ses:SendRawEmail"],
      "Resource": [
        "arn:aws:ses:us-east-1:111122223333:identity/mail.example.com",
        "arn:aws:ses:us-east-1:111122223333:configuration-set/systemauth-transactional"
      ],
      "Condition": {
        "StringLike": {"ses:FromAddress": "*@mail.example.com"}
      }
    }
  ]
}
```

`mail.ses.region` selects the region; without it the region comes from
`AWS_REGION` or the profile. SES addresses must be ASCII: encode an
internationalized domain as Punycode.

## 8. Check it

1. Start SystemAuth with the configuration and sign in with a provider
   account whose email is unverified (or request an email change at
   `/account/email`).
2. Confirm the message arrives and its headers show `dkim=pass`,
   `spf=pass` for the MAIL FROM domain, and `dmarc=pass`.
3. Send to the SES mailbox simulator (`bounce@simulator.amazonses.com`,
   `complaint@simulator.amazonses.com`) by requesting an email change to it,
   and confirm the configuration set's event destinations receive the
   events.

Production mode refuses `mail.provider: log`; use SES or SMTP in every
deployment that serves real users.
