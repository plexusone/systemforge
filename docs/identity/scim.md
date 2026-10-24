# SCIM Provisioning

`identity/scim` serves SCIM 2.0 (RFC 7643/7644) so an enterprise identity
provider such as Okta or Microsoft Entra ID can provision users. The Ent store
(`identity/scim/store`) maps SCIM Users to human principals and SCIM Groups to
organizations.

## Credentials Are Bound to an Organization

Every SCIM request runs in a provisioning scope. Authenticate requests with
`CredentialMiddleware`, returning the organization the credential belongs to:

```go
api, err := scim.NewAPI(provider)
if err != nil {
    return err
}
router.Mount("/scim/v2", api.CredentialMiddleware(func(r *http.Request) (scim.Credential, error) {
    tok, err := scimTokens.Verify(r.Context(), bearerToken(r))
    if err != nil {
        return scim.Credential{}, err
    }
    return scim.Credential{
        Subject: tok.ID,
        Scopes:  []string{scim.ScopeFull},
        Scope:   scim.Scope{OrganizationID: tok.OrganizationID},
    }, nil
})(api))
```

The store refuses any request without a scope (403), so a credential must be
bound to exactly one organization, or explicitly to the platform.

## What a Tenant Credential Can Do

A credential bound to an organization manages that organization's members:

| Operation | Behavior |
|-----------|----------|
| List or get users | Only members of the organization, active or suspended |
| Create a user | Creates the user and makes them a member. If the email already belongs to a user, that user is added as a member and their identity is unchanged |
| Update a user | `active` suspends or restores the membership. Email, name and photo change only for users the organization owns |
| Delete a user | Removes the membership; deletes the account only when the organization owns it |
| Groups | The organization is the only group. Members can be added and removed; the group cannot be created, renamed or deleted |

An organization **owns** a user it provisioned who belongs to no other
organization. A user who also belongs elsewhere, such as a person with a
personal account or a member of another organization, is shared: the
organization's identity provider manages only their membership, so it cannot
change a login email used elsewhere.

## Membership Changes

The store changes memberships only through the organization service, so a
SCIM change has the same effects as any other: the authorization graph is
synced, an access change is recorded so existing tokens stop being honored,
and a removed member's application roles and resource grants go with the
membership. Pass the application's configured services:

```go
st := store.NewEntStore(client, &store.Config{
    BaseURL:     "/scim/v2",
    DefaultRole: "member",
    Memberships: orgService,       // organization.Service with the authz syncer
    Principals:  principalService, // principal.Service
})
```

Without them the store builds services on its Ent client: access changes are
still recorded, but no authorization graph is synced, which a SpiceDB
deployment needs.

Two rules apply on top:

- An organization owner is never suspended, removed or deleted through SCIM
  (403), so an identity provider cannot lock a customer out of its own
  organization. Transfer ownership first.
- A restored membership (`active` back to true, or re-adding a removed member
  to the group) gets the default role, not the role it had before, because
  the identity provider does not manage roles.

Creating a user adds the account first and the membership after. If adding
the membership fails, the request fails; the identity provider's retry finds
the account by email and links it.

## Platform Operator Credentials

A credential with `scim.Scope{Platform: true}` provisions every user and
organization, as SCIM did before scoping. For it, `active` deactivates or
reactivates the account itself. Issue it only to platform operators,
never to a customer's identity provider.
