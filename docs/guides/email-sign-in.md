# Launching with Email Sign-In

Email sign-in lets people use an application on day one, before its GitHub or
Google sign-in has been reviewed, and it keeps working for people who have
neither. This guide turns it on for a deployment and an application, step by
step. The reference is [Sign In with an Email Code](../systemauth/email-sign-in.md).

## 1. Choose a mail provider

Codes are mail, so delivery decides whether anyone can sign in.
SystemAuth sends through [omnimail](https://github.com/plexusone/omnimail),
so the provider is a setting:

- [Resend](../systemauth/resend-deployment.md) over SMTP needs no new code, and
  its free plan allows 100 messages a day, so plan for a paid one if several
  applications share the account.
- [Amazon SES](../systemauth/ses-deployment.md) needs its sending identity
  verified, and may need production access approved before it sends to anyone.

Verify the sending domain (SPF, DKIM, DMARC) before launch.

## 2. Configure SystemAuth

```yaml
social_login:
  email: {}              # turns it on; or set code_length, code_lifetime, max_attempts
mail:
  provider: smtp
  from: "Example <no-reply@mail.example.com>"
  smtp:
    host: smtp.resend.com
    port: 465
    security: tls
    username: resend
    password: ${SYSTEMAUTH_SMTP_PASSWORD}
tokens:
  hmac_secret: ${SYSTEMAUTH_HMAC_SECRET}
```

`tokens.hmac_secret` keys the code hash and is required in production; without
it codes stop working on a restart and on a second instance. Production
refuses `mail.provider: log`. If several instances serve SystemAuth, give them
shared [rate limit storage](rate-limiting.md), or the send limits that bound
guessing apply per instance. Run `systemauth migrate` once for the new column.

You can keep `github` and `google` beside it; the sign-in page lists each.

## 3. Check delivery

Request a code for addresses at two mailbox providers, from the production
domain, and read the headers: SPF, DKIM and DMARC should pass and align. The
[delivery check](../systemauth/resend-deployment.md#delivery-check) lists the
steps. Make sure the deployment records security events (the packaged
`systemauth` command logs them; an embedding application sets an audit
emitter), so you can see `systemauth.email_code.sent` with `sent: true`.

## 4. Point the application at it

With the relying-party BFF, link to `/bff/auth/email?return_to=/path`. With
`@plexusone/pages`, add `email` to the login page:

```tsx
<LoginPage oauthProviders={['github', 'google', 'email']} />
```

Better, build the buttons from the deployment so a method turned on in
SystemAuth's configuration shows up without a change to the application: read
`GET /bff/auth/methods` (in React, `useSignInMethods` from the
`@plexusone/auth` release that accompanies v0.39.0), or in Go
`SocialLoginConfig.SignInMethods()` and `Server.SignInMethods()`. SystemAuth
publishes its methods in its discovery document and the BFF lists them
([relying parties](../systemauth/relying-party.md)); no provider list is written
in the application.

Deploy SystemAuth and the BFF before the page: an older BFF answers
`UNKNOWN_PROVIDER` when the button is clicked. The application never receives
the code; it receives the verified address afterward, as for any provider.

## 5. Decide who may sign up

A new account is asked for its name, and optionally a workspace name, before
it is created, so every application gets a real `name` and none needs its own
prompt. Nothing is taken from the address.

Email sign-in creates accounts for addresses nobody has seen, so the sign-up
controls matter: a [minimum age](signup-age.md), and
[invite-gated sign-up](invite-gated-signup.md), which applies to email exactly
as to a provider.

## Managed people

Email sign-in creates ordinary accounts with no managers. A managed principal,
such as a child a parent or teacher manages, has no email and cannot be reached
by an email code or by a social login: sign-in by address matches only a
**verified** email.

A host that gives a managed principal an address
(`managedprincipal.Service.AttachVerifiedEmail`) turns that address into a sign-in
key by email code, and by social login only when the provider is authoritative
for the address (Google for its consumer domains and for a Workspace account's
own domain; GitHub is not, so a GitHub sign-in with an address already attached
is refused as a conflict and links nothing), on purpose: management does not depend
on the email ([ADR-009](../design/adrs/ADR-009-management-is-a-relationship.md)),
and a child may have their own address, such as a school one. Management
continues, and the managers keep their authority. So attach only an address the
person controls and has proved, not one a guardian typed; SystemAuth's mailed
code is that proof.

An address on a managed principal that is **not** verified is not a sign-in key,
but it still holds the address: a person who later signs up with it is refused as
a conflict. A host that proxies `POST /managed-principals/` should not forward an
arbitrary `email`.

## What to watch

- `systemauth.email_code.exhausted` events: codes that used up their tries.
  Many from one client address, or many for one address, are guessing.
- `systemauth.email_code.sent` events with `sent: false`: a limit suppressed
  the message, or delivery failed.
- Bounce and complaint rates at the mail provider.

A person who changes their account's email stops being reachable at the old
address: its email identity is unlinked, and the old mailbox gets an account of
its own if it signs in again.
