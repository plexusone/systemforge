# ADR-024: Names Are Supplied, Not Derived from the Email Address

**Status:** Accepted
**Deciders:** @grokify
**Relates to:** ADR-002 (centralized social login), ADR-023 (email code sign-in)

## Context

A person who signs in with an emailed code (ADR-023) gives SystemAuth an
address and nothing else. SystemAuth filled the gaps from the address: the
display name became the address itself, and the personal organization was
named and slugged from the part before the `@`. The display name is sent to
every relying party in the `name` claim, and applications show it to other
people on public profiles, in member lists and on printed certificates. An
address is not the person's to publish, and a handle made from it publishes
most of it.

The same fallbacks applied to any social login whose provider gave no name.

## Decision

1. **Nothing is derived from the email address.** The display name is the
   name the person gave, or the provider's handle (a GitHub login), and never
   the address. The personal organization is named with the name the person
   gave for it, else their name, else their handle; its slug is the provider's
   handle or a generated one, never made from the address. The one fallback
   left, for a directory used without the sign-up step, is the neutral name
   "Member".
2. **SystemAuth asks.** When an account is about to be created for a login
   with no name, it asks, before creating anything, for the person's name and
   optionally a name for their personal workspace. A name is up to 100
   characters, printable, and not an email address (no `@`); the workspace
   name is up to 80. The answer goes through a form on `/signup/name`, so every
   application that federates to SystemAuth gets a real `name` claim and none
   has to ask itself.
3. **The sign-up waits, proven and bound to the browser.** The proven login
   (provider identity, address and what proved it, the invite and age answers)
   is parked in the verification token store under a new purpose, bound to the
   browser by a cookie, for 15 minutes. The form is protected by an origin
   check and a form token derived from the cookie, and answering uses the
   parked sign-up once, so two answers cannot create two accounts. Nothing is
   created until the form is answered.
4. **Order.** The sign-up gate (invites), then the age question, then the name
   question: a person who will be refused is not asked for a name. An existing
   account is never asked.
5. **The store exists without mail.** A deployment with GitHub or Google and no
   `mail` section builds the verification token store as well, since parking
   needs it.
6. **Hosts list methods from SystemAuth.** `SocialLoginConfig.SignInMethods`
   and `Server.SignInMethods` give the methods a deployment offers, so hosts do
   not hard-code the provider list.

## Consequences

- Every host gets a `name` that the person chose, including on certificates
  and public profiles, with no change of its own. A host that had its own name
  prompt for email accounts no longer needs it for new accounts.
- A sign-up takes one more step for logins that give no name. GitHub gives a
  handle when it gives no display name, so only a login with neither is asked.
- Accounts created before this change keep the names they have; a person who
  signed up by email earlier may still have their address as their name.
  Changing a name is not offered yet.
- The package `identity/displayname` is the one place a name that is missing,
  or is an address, becomes something safe to show (`Show`, `Safe`, `Or`; the
  neutral default is "Member"). The relying-party stores, `oauthclient`, the
  SCIM store and SystemAuth's own directories use it, so no layer falls back to
  the address, and a host calls it instead of writing its own guard. (The first
  release of this ADR left the relying-party stores and `oauthclient` falling
  back to the address; v0.39.0 replaces that.) A profile whose name field holds
  an address is treated as having no name, and the person is asked.
- The same rule applies to later writes: a sign-in, a SCIM update or a
  federation update that carries no name, or an address, keeps the stored name.
- SystemAuth leaves the `name` claim out when the stored name is an address,
  as an older account's may be, so no application receives one as a name. The
  address is still the `email` claim. A relying party handles a missing `name`:
  the stores in this library keep the name they have, or use "Member".
- The sign-in methods page's linked-provider list, which the sign-up wrappers
  had hidden from deployments with a gate or an age check, is read from the
  directory itself again.

## Alternatives considered

- **Omit the `name` claim when it is the address.** Hides the address from
  hosts but leaves every host to ask for a name, and every host with the same
  trap to solve it.
- **Ask on the address form, before the code.** Needs no parked state, but asks
  people who already have an account, and cannot tell them apart without
  revealing which addresses have one.
- **Require a name for every sign-in method in configuration.** A setting adds
  paths to test; asking whenever there is no name is the behavior wanted
  everywhere.
