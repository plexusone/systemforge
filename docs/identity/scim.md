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

## Platform Operator Credentials

A credential with `scim.Scope{Platform: true}` provisions every user and
organization, as SCIM did before scoping. Issue it only to platform operators,
never to a customer's identity provider.
