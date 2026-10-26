# Minimum Sign-Up Age

A deployment for adults, or one that must keep children from creating their
own accounts, sets a minimum sign-up age. SystemAuth then asks a person's
birth month and year before their first upstream login creates an account,
and refuses anyone younger, keeping nothing about them.

## What a person sees

1. They choose **Continue with Google** (or GitHub) and sign in there, as
   usual.
2. If they have no account yet, SystemAuth shows **Before you create an
   account** on `/signup/age`: a month and a year, both empty.
3. **At or over the age,** they are sent back through the provider, which
   usually returns at once without asking again, and their account is
   created. They land where sign-in was going.
4. **Under the age,** they are told they need to be older and that nothing
   about them has been kept. The same browser is not asked again for a day.

People who already have an account never see the question. Neither do
children signing in with login tokens: they are managed principals, created
by their managers, not by an upstream login.

## Turning it on

In the SystemAuth configuration:

```yaml
social_login:
  google:
    client_id: ${SYSTEMAUTH_GOOGLE_CLIENT_ID}
    client_secret: ${SYSTEMAUTH_GOOGLE_CLIENT_SECRET}
  signup_minimum_age: 18
```

`0`, the default, asks nothing. Values from 1 to 120 are accepted; anything
else fails at startup with `ErrInvalidSocialLoginConfig`.

A host binary can change the page's wording; `%d` in `Message` and
`Refused` is replaced by the minimum age:

```go
svc, err := systemauthsvc.New(ctx, cfg, systemauthsvc.Options{
    SignupAgePage: systemauth.SignupAgePage{
        Title:   "Before you join",
        Message: "Accounts are for parents and teachers, %d or older. When were you born?",
    },
})
```

Empty fields keep `systemauth.DefaultSignupAgePage`. An embedded server
takes the same wording with `systemauth.WithSignupAgePage`.

## How it decides

- **Nothing is kept before the answer.** The login is parked with only its
  provider and where it was going, in the login-state store, for 15
  minutes. The provider's email, name and identifiers are not stored.
- **The question is neutral.** Month and year start empty, and the year
  list runs from this year back 120 years, including years too recent to
  pass, so it does not hint at the answer.
- **The birth month counts in full.** Without the day, SystemAuth assumes
  the last day of the birth month, so nobody younger than the minimum
  passes. Someone whose birthday falls later this month is asked to come
  back after it.
- **Each answer is used once.** The parked login and the confirmation that
  restarts it are single-use and short-lived. An incomplete answer, such as
  a missing month, can be corrected without starting over.
- **Answers come from SystemAuth's own pages.** A `POST /signup/age` from
  another origin is refused with `403`.
- **The answer is never stored.** Neither is the login of a person who was
  refused. Only the refusal is logged, with the provider and nothing about
  the person.

## With invite-only sign-up

With invite-only sign-up on, the invite is checked first. An uninvited
login is refused, or sent to the waitlist, without being asked its age. An
invited login is asked, and its invite is used only once the age is
confirmed, so a refused answer leaves the invite for its rightful holder.

## Trying it locally

With `insecure_cookies: true` for plain HTTP, sign in with an account the
deployment has not seen. To be asked again after a refusal, clear the
`sf_signup_age_refused` cookie; over HTTPS it is
`__Host-sf_signup_age_refused`.

## Limits

- The question is a stated age, not a verified one. It keeps children from
  creating their own accounts; verifying a parent's consent for a child is
  the application's responsibility.
- The refusal is remembered per browser. A person who clears their cookies
  can answer again.
- Accounts created before the minimum age was set are not asked.
- Only accounts created by an upstream social login are asked. Accounts
  created another way are not: by an application calling `signup.Service`
  (`Signup`, `SignupWithInvite`, `SignupOrGetExisting`), by federation sync
  from a hub, by SCIM provisioning, or as managed principals. An application
  that offers its own self-service sign-up must ask the age itself before it
  calls `signup.Service`; a federation hub or SCIM client is trusted to have
  applied its own policy.
