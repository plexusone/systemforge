# ADR-019: Support Requests and Feedback in Every Application

**Status:** Proposed
**Deciders:** @grokify
**Relates to:** ADR-003 (omnimail, which the default desk uses), ADR-011 and
ADR-012 (classification, privacy rights and holds, which cover support
requests), ADR-013 (keys, which can seal message text), ADR-017 (the same
adoption pattern as connectforge), ADR-007 (organization and platform roles),
ADR-020 (customer-authorized support access, and staff masking), ADR-016
(OAuth grants, which the support tools use).
**Builds on:** [supportforge](https://github.com/plexusone/supportforge),
the generic support-request library, and
[supportforge-core](https://github.com/plexusone/supportforge-core), its
dependency-free desk interface.

## Context

An application built on SystemForge is usually launched by a small team, and
its first users are the ones most worth hearing: what confused them, what
broke, what they wish it did. Without a built-in way to reach the team, an
application ships with no contact path at all, and early problems and
opinions are lost. Each team then builds its own form, against whichever help
desk it happens to pick, without the platform's identity, audit or privacy
rules.

The needs are the same in every application:

- **A way to ask for help and a way to give feedback,** from a signed-in user
  or a visitor, from the first day.
- **Honest expectations.** Small teams are not online. A reply by email,
  later, is the promise they can keep, and a chat widget is not.
- **Nothing lost.** A help desk that is down, rate-limited or misconfigured
  must not swallow a message.
- **Personal data under the platform's rules.** Support messages hold names,
  addresses and free text, and must be covered by export, erasure and holds
  like the rest of a user's data.
- **No lock-in.** Help desks differ in free tiers, APIs and limits, and a team
  may change desks as it grows.

None of this is specific to identity, so the mechanism is its own module,
supportforge, usable outside SystemForge. This ADR records how the platform
adopts it, as ADR-017 does for connectforge.

## Decision

1. **SystemForge adopts supportforge as its one mechanism for support
   requests and feedback.** A thin `support` package composes it with the
   platform, as `connections` does for connectforge.
2. **It is always included and on.** Every SystemForge application has
   working "Contact support" and "Send feedback" from its first deployment.
   - **Why always.** Launching a SaaS means hearing its users, and the cost
     of the capability is a few tables and a background job. An optional
     component would be left out of exactly the early launches that need it
     most.
   - **How it works with nothing configured.** The default desk is mail
     through omnimail, which every deployment already configures for
     verified email (ADR-003). A deployment sets its support address and
     needs nothing else. A help desk is added by configuration.
3. **supportforge owns its schema.** SystemForge runs its migration on the
   platform database. Its tables are prefixed `supportforge_` and are not
   merged into SystemForge's Ent client.
4. **The import direction is one way.** SystemForge imports supportforge,
   which imports supportforge-core. A desk adapter imports only
   supportforge-core and nothing from SystemForge, so adapters can live in
   vendor SDKs, in applications or in private repositories. SystemForge ships
   no vendor desks. The `support` package supplies supportforge's ports:

   | supportforge port | SystemForge implementation |
   | --- | --- |
   | Requester resolution | The session: principal, organization and verified email; never the request body |
   | `ChallengeVerifier` | The deployment's bot challenge, for visitor requests |
   | `RateLimiter` | The platform rate limiter, keyed by principal or challenge token |
   | `HoldChecker` | Legal holds (ADR-012) |
   | `Cryptographer` | keyforge, purpose `supportforge.case` (ADR-013), when sealing is enabled |
   | `Observer` | A hook the application may connect to its analytics; the notice carries no text |
   | Audit | The platform audit trail, with no personal data |
   | Catalog registration | supportforge's classification, registered with the data catalog (ADR-011, ADR-012) |

5. **Requests belong to the deployment, not to the requester's
   organization.** The operator of the application answers them. The
   requester's organization is recorded as context, for export, and for what
   that organization's administrators may see:
   - **The index, always.** Organization owners and admins see their
     organization's requests without the text: who filed, kind, product,
     status and dates.
   - **The text, when the requester shares it.** The form offers "share with my
     organization's admins", off by default. An organization may set a policy
     that shares every request from its members, and the form then says so
     before anyone types.
   - **Billing requests are shared.** Billing belongs to the organization
     (ADR-007), so requests of kind `billing` are visible in full to its
     owners and admins, and the form says so.
   - **Never to members or collaborators.** Only owners and admins see other
     people's requests.

   A request is written to the operator, not to the employer, so sharing its
   text with the organization is a separate purpose the requester agrees to,
   not a default.
6. **Support has its own permissions.** `support.request.read` lets a
   holder list and read requests through the API, which matters when mail is
   the only desk. `support.desk.configure` lets a holder change the desk
   order and redeliver. `support.reply.draft` lets a holder draft a reply,
   and `support.reply.approve` lets a holder approve and send one. They are
   held by a platform role, `support_agent`, separate from platform
   administration, in the vocabulary of ADR-007 and ADR-012. A grant issued to
   an agent (decision 13) never carries `support.reply.approve`, even when
   the person who authorized it holds the role. Reading a
   request's own text needs no customer grant. Looking at the customer's
   application data does, under ADR-020.
7. **The API:**

   ```text
   POST /api/v1/support/requests          signed in; requester from the session
   POST /api/v1/public/support/requests   visitor; bot challenge required
   GET  /api/v1/support/requests/mine     signed in; the requester's own requests
   GET  /api/v1/support/requests          support_agent; list, without cleared text
   GET  /api/v1/support/requests/{ref}    support_agent
   POST /api/v1/support/requests/{ref}/redeliver   support.desk.configure; retry, or skip to the next desk
   POST /api/v1/support/requests/{ref}/replies     support.reply.draft; a draft reply
   POST /api/v1/support/replies/{id}/approve       support.reply.approve; a person; sends it
   GET  /api/v1/organizations/{org}/support/requests        owners and admins; index, plus shared text
   GET  /api/v1/organizations/{org}/support/requests/{ref}  owners and admins
   ```

   - **The response to a new request** is its reference and the promise of an
     email reply, with no time given.
   - **A listed request** carries its reference, kind, product, title, date
     and status (`received`, `delivered`, `open`, `pending` or `closed`). It
     carries a `deskUrl` only when the desk has a page the requester can sign
     in to. A desk that cannot report status leaves it at `delivered`.
   - **The title is kept while the request is listed,** so a requester can
     recognize it. The body and reply address are cleared as decision 8
     says. Visitors have no list; they follow their request
     by email.
8. **Personal data follows the platform's rules.**
   - **Classification.** supportforge classifies every field, and SystemForge
     registers them, so `Export` and `Erase` cover requests.
   - **Clearing.** By default:
     - the body is cleared seven days after delivery;
     - the reply address is kept while the conversation may continue, and
       cleared seven days after the latest of delivery, the last reply, and
       the desk closing the ticket, so a reply can still reach the requester
       through the mail desk;
     - a ceiling clears the address after 90 days without activity, even if
       the desk still shows the ticket open;
     - the title is cleared with the index (decision 7).
   - **The desk.** Erasure reaches the desk where its adapter supports it.
     Where it cannot, the request is reported as retained at the desk.
   - **Holds.** A hold stops both clearing and erasure.
   - **Retention of the remaining index** is a deployment policy input
     (ADR-011 decision 11).
9. **Desks are configured per deployment and per product.** A desk's
   credentials belong to the operator's own account at the vendor, so they are
   deployment secrets read through omnivault, not organization connections.
   The desk order always ends with mail.
10. **The user interface is shared, and it is ours.** One package in
    systemforge-web, `@plexusone/support`, built over the API and embedded by
    every application:
    - **A support button and panel** with "Contact support" and "Send
      feedback". The panel holds a form, not a conversation. It shows the
      sharing choice, says when a policy or the kind already shares the
      request, and confirms with the reference and the promise of an email
      reply.
    - **"My requests"**, from the requester's own list, with a link to the
      desk only where `deskUrl` is given.
    - **The organization view,** which the organization console mounts.
    - **Later, an embeddable element** for pages that are not React, such as
      a visitor contact form on a marketing site, as a second entry point of
      the same package.

    It loads no vendor script and stores nothing in the browser. Its copy
    promises a reply by email, and nothing suggests anyone is online. Screens
    an application marks as for children do not load it. A vendor's own
    widget is not used: it brings a chat, a third-party script and browser
    storage, and a request filed there would skip the platform's store,
    fallback and privacy rules.
11. **It runs in process.** Intake is part of the API, and the delivery worker
    and clear job run as platform jobs.
12. **Responders answer in the desk, so the platform has no support console
    at first.** A help desk such as PostHog Support brings its own inbox, and
    with the mail desk the operator's mailbox is the inbox, since each request
    arrives with `Reply-To` set to the requester. What the operator needs from
    the platform at first is an alert when delivery fails. An agent console, a
    knowledge base with suggested answers, and a chat answered by people or
    agents are later products built on top of this one, not part of it.
13. **Operators reach support through agent-first tools.** A `support`
    command in the SystemForge CLI and an MCP server, both thin adapters over
    one Go client of the API in decision 7:
    - **First:** list and read requests by kind, product, status and date; a
      digest of feedback by product; failed and stuck deliveries, with retry
      and skip to the next desk; and a request's conversation, read from the
      desk through its export.
    - **Next:** an agent drafts a reply, and it is sent to the requester only
      after a person approves it:
      - **The draft is stored by the platform,** as personal data classified
        like the request's body, and cleared once sent or discarded.
      - **A person approves the exact text.** Approval needs
        `support.reply.approve`, which an agent's grant never holds, so an
        agent cannot approve its own draft. An edit after approval needs a
        new approval.
      - **Sending follows approval,** through the desk, so the reply joins
        the ticket's conversation. A desk that cannot send replies keeps the
        draft as a note for a person to send there.
      - **The audit trail records** who drafted, who approved, and when it
        was sent.
    - **Not allowed:** an agent sending a reply no person approved.

    The tools act as a principal holding `support.request.read`,
    `support.reply.draft`, and `support.desk.configure` for delivery
    operations, through an OAuth grant (ADR-016). Every read is audited. A request's text needs no customer
    grant, but the customer's application data still does (ADR-020). An
    operator who passes request text to a model provider adds that provider
    as a processor, under a processing agreement and in the privacy notice.

## Consequences

- **Every application can hear its users at launch,** with no vendor account
  and no extra work beyond a support address.
- **Product code stays vendor-neutral.** Changing help desks is a
  configuration change, and an adapter can be written anywhere.
- **More tables in the platform database,** owned and migrated by another
  module, and two more background jobs.
- **Mail is the floor.** A deployment without working outbound mail has no
  support delivery. It already lacks verified email, so this adds no new
  requirement.
- **Requests are personal data in the platform's governance,** so privacy
  requests and holds include them without each application's help.
- **No console to build or run at launch.** Responders use the desk's inbox
  or a mailbox, and operators use the CLI or an agent. The price is that a
  mail-only deployment has no shared view of who is answering what.
- **Agents can answer requesters, but never alone.** Every agent reply
  passes through a person's approval, which the platform enforces, at the
  cost of a step before each reply.
- **Requesters see their requests in the application,** with a status only
  as current as the desk can report, and a link out only where the desk has a
  page for them.
- **Visitors' text is never echoed** in acknowledgments. A visitor sees only
  that their request was received, which is the price of not relaying
  arbitrary mail from the operator's domain.

## Alternatives considered

- **Each application builds its own form.** Rejected: repeated work, no
  shared identity, audit or privacy rules, and many applications would launch
  without one.
- **Optional component, off by default.** Rejected: the purpose is that every
  launch has it. The cost of including it is small, and its default needs no
  vendor.
- **A vendor chat widget.** Rejected for the default: it implies a live
  conversation, brings a vendor script and browser storage, and ties
  applications to one vendor. A live channel remains a later product.
- **Send requesters to the desk's own portal.** Rejected: PostHog Support
  has none, and a desk that has one, such as Zoho Desk's help center, needs a
  second account at the vendor. A link to it is offered where it exists.
- **A support console in the first release.** Rejected: the desks already
  have inboxes, and the operator's first need, knowing when delivery fails,
  is met by alerts and the agent-first tools.
- **Approval in the agent's client only.** Rejected: a confirmation prompt
  in a CLI or MCP client cannot be checked by the platform. Approval is a
  separate call by a person, under a permission agents do not hold.
- **The UI in its own repository.** Rejected for now: it calls this
  platform's API and uses its session, components and design tokens, so it
  would move in step with systemforge-web anyway. It can move later under the
  same package name.
- **Build it inside SystemForge.** Rejected for the same reasons as keyforge
  and connectforge: it is not specific to identity, it deserves its own
  review, and other hosts can use it.
- **Put it in a knowledge or answers module.** Rejected: approved knowledge is
  long-lived and mostly public, while support requests are short-lived
  personal data. The two connect through suggested answers, not shared
  storage.
