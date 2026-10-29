package ocsfaudit

import (
	"github.com/google/uuid"
	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
)

// Authentication protocols of sign-in methods. A method not listed is
// recorded as protocol Other with the method as its label.
var signInProtocols = map[string]int{
	"google": events.AuthenticationAuthProtocolIDOpenID,
	"github": events.AuthenticationAuthProtocolIDOAUTH20,
	"oidc":   events.AuthenticationAuthProtocolIDOpenID,
	"saml":   events.AuthenticationAuthProtocolIDSAML,
}

func (a *authentication) protocol(id int, label string) {
	a.AuthProtocolID = id
	a.AuthProtocol = events.AuthenticationAuthProtocolIDCaptions[id]
	if id == events.AuthenticationAuthProtocolIDOther {
		a.AuthProtocol = label
	}
}

// signInMethod sets the protocol from a sign-in method.
func (a *authentication) signInMethod(method string) {
	if method == "" {
		return
	}
	if id, ok := signInProtocols[method]; ok {
		a.protocol(id, "")
		return
	}
	a.protocol(events.AuthenticationAuthProtocolIDOther, method)
}

// clientActor names the OAuth client of the client_id detail as the
// actor's application. When SystemAuth itself is the actor's application,
// the client ID stays in unmapped.
func (c *common) clientActor() {
	clientID := c.d.get("client_id")
	if clientID == "" {
		return
	}
	if c.actor == nil {
		c.actor = &objects.Actor{}
	}
	if c.actor.Application == nil {
		c.actor.Application = &objects.Application{UID: clientID, Type: "oauth_client"}
		delete(c.d, "client_id")
	}
}

// signIn: Authentication, Logon.
func (c *common) signIn() any {
	method := c.d.take("method")
	c.clientActor()
	a := c.authentication(events.AuthenticationActivityIDLogon, user(c.ev.Actor.ID, "principal"))
	a.signInMethod(method)
	return a
}

// signOut: Authentication, Logoff.
func (c *common) signOut() any {
	method := c.d.take("method")
	a := c.authentication(events.AuthenticationActivityIDLogoff, user(c.ev.Actor.ID, "principal"))
	a.signInMethod(method)
	return a
}

// tokenRequest: a refused token request, or a replayed refresh token or
// authorization code: Authentication, Logon, OAuth 2.0. A replay is High.
func (c *common) tokenRequest() any {
	clientID := c.d.get("client_id")
	c.clientActor()
	var u *objects.User
	if c.d.get("grant_type") == "client_credentials" && clientID != "" {
		u = clientUser(clientID)
	}
	switch c.ev.EventType {
	case "systemauth.refresh_token.reuse":
		c.severityID, c.statusDetail = events.SeverityIDHigh, "refresh_token_reuse"
	case "systemauth.authorization_code.reuse":
		c.severityID, c.statusDetail = events.SeverityIDHigh, "authorization_code_reuse"
	}
	a := c.authentication(events.AuthenticationActivityIDLogon, u)
	a.protocol(events.AuthenticationAuthProtocolIDOAUTH20, "")
	return a
}

// tokenRevocation: a token revoked at the revocation endpoint, or a token
// family revoked by SystemAuth: Authentication, Logoff, OAuth 2.0.
func (c *common) tokenRevocation() any {
	c.clientActor()
	var u *objects.User
	if sub := c.d.take("subject"); sub != "" {
		u = &objects.User{UID: sub}
	}
	a := c.authentication(events.AuthenticationActivityIDLogoff, u)
	a.protocol(events.AuthenticationAuthProtocolIDOAUTH20, "")
	return a
}

// email: a step of email verification. Verifying the address of a
// sign-in is a pre-authentication step (Authentication, Preauth); a step
// of changing an account's address is User Management, Update. The
// address itself is never recorded.
func (c *common) email() any {
	if c.d.get("purpose") == "verify_email" {
		method := c.d.take("method")
		a := c.authentication(events.AuthenticationActivityIDPreauth, c.subject())
		a.signInMethod(method)
		return a
	}
	return c.userManagement(events.UserManagementActivityIDUpdate, c.subject())
}

// startup: the signing key loaded and the production checks waived at
// startup: Application Lifecycle, Start. A waiver is Medium.
func (c *common) startup() any {
	if c.ev.EventType == "systemauth.production.waiver" {
		c.severityID = events.SeverityIDMedium
		if check := c.d.get("check"); check != "" {
			c.statusDetail = "production check waived: " + check
		}
	}
	return c.applicationLifecycle(events.ApplicationLifecycleActivityIDStart)
}

// Membership actions as Group Management activities.
var membershipActivities = map[string]int{
	"added":                 events.GroupManagementActivityIDAddUser,
	"removed":               events.GroupManagementActivityIDRemoveUser,
	"updated":               events.GroupManagementActivityIDUpdate,
	"ownership_transferred": events.GroupManagementActivityIDUpdate,
}

// membership: Group Management, the organization as the group and the
// member as the user. A transfer of ownership is Medium.
func (c *common) membership() any {
	activity, ok := membershipActivities[c.ev.Action]
	if !ok {
		activity = events.GroupManagementActivityIDUpdate
	}
	if c.ev.Action == "ownership_transferred" {
		c.severityID = events.SeverityIDMedium
	}
	org := c.d.take("organization_id")
	if org == "" {
		org = c.metadata.TenantUID
	}
	g := &objects.Group{UID: org, Type: "organization"}
	if org == "" {
		g = &objects.Group{Name: "organization", Type: "organization"}
	}
	u := user(c.ev.Resource.ID, "principal")
	if id := c.d.take("principal_id"); id != "" {
		u = &objects.User{UID: id}
	}
	return c.groupManagement(activity, g, u)
}

// platformAdmin: User Management, Assign or Remove Privileges
// (platform_admin). A grant is High.
func (c *common) platformAdmin() any {
	activity := events.UserManagementActivityIDRemovePrivileges
	if c.ev.Action == "granted" {
		activity = events.UserManagementActivityIDAssignPrivileges
		c.severityID = events.SeverityIDHigh
	}
	um := c.userManagement(activity, c.subject())
	um.Privileges = []string{"platform_admin"}
	return um
}

// Service-account actions as User Management activities.
var serviceAccountActivities = map[string]int{
	"created":      events.UserManagementActivityIDCreate,
	"disabled":     events.UserManagementActivityIDDisable,
	"enabled":      events.UserManagementActivityIDEnable,
	"deleted":      events.UserManagementActivityIDDelete,
	"key_added":    events.UserManagementActivityIDAddProgrammaticCredentials,
	"key_revoked":  events.UserManagementActivityIDRemoveProgrammaticCredentials,
	"role_granted": events.UserManagementActivityIDAssignRoles,
	"role_removed": events.UserManagementActivityIDRemoveRoles,
}

// serviceAccount: User Management, the service account as a Service user.
// A key is recorded by its key ID, a role by its name.
func (c *common) serviceAccount() any {
	activity, ok := serviceAccountActivities[c.ev.Action]
	if !ok {
		activity = events.UserManagementActivityIDUpdate
	}
	u := user(c.ev.Resource.ID, "service_account")
	if u != nil && c.metadata.TenantUID != "" {
		u.Org = &objects.Organization{UID: c.metadata.TenantUID}
	}
	c.d.take("organization_id")
	if u != nil {
		if keyID := c.d.take("key_id"); keyID != "" {
			u.ProgrammaticCredentials = []objects.ProgrammaticCredential{{UID: keyID, Type: "service_account_key"}}
		}
	}
	var roles []objects.IAMRole
	if role := c.d.get("role"); role != "" {
		roles = []objects.IAMRole{{Name: role}}
	}
	um := c.userManagement(activity, u)
	um.IAMRoles = roles
	return um
}

// keyActivities maps key lifecycle actions to Entity Management
// activities. Actions not listed are Update.
var keyActivities = map[string]int{
	"key.created":             events.EntityManagementActivityIDCreate,
	"key.activated":           events.EntityManagementActivityIDActivate,
	"key.retired":             events.EntityManagementActivityIDDeactivate,
	"key.destroyed":           events.EntityManagementActivityIDDelete,
	"dek.destroyed":           events.EntityManagementActivityIDDelete,
	"subject.shred_completed": events.EntityManagementActivityIDDelete,
	"admin.read":              events.EntityManagementActivityIDRead,
	"guard.denied":            events.EntityManagementActivityIDRead,
	"guard.pending":           events.EntityManagementActivityIDRead,
}

// keySeverities raises the severity of key lifecycle actions that call
// for attention.
var keySeverities = map[string]int{
	"key.compromised":         events.SeverityIDHigh,
	"dek.compromised":         events.SeverityIDHigh,
	"key.destroyed":           events.SeverityIDMedium,
	"dek.destroyed":           events.SeverityIDMedium,
	"subject.shred_requested": events.SeverityIDMedium,
	"subject.shred_completed": events.SeverityIDMedium,
	"wrap.failed":             events.SeverityIDMedium,
	"guard.denied":            events.SeverityIDMedium,
	"job.failed":              events.SeverityIDMedium,
	"backup.stale":            events.SeverityIDMedium,
}

// keys: key lifecycle events, Entity Management of the key, by its key ID
// and version. No key material is ever in the event.
func (c *common) keys() any {
	activity, ok := keyActivities[c.ev.Action]
	if !ok {
		activity = events.EntityManagementActivityIDUpdate
	}
	if sev, ok := keySeverities[c.ev.Action]; ok && sev > c.severityID {
		c.severityID = sev
	}
	return c.entityManagement(activity, c.entity("key"))
}

// connectionActivities maps connection events to Entity Management
// activities. Events not listed are Update.
var connectionActivities = map[string]int{
	"connection.created":      events.EntityManagementActivityIDCreate,
	"connection.validated":    events.EntityManagementActivityIDRead,
	"connection.disconnected": events.EntityManagementActivityIDDeactivate,
	"connection.deleted":      events.EntityManagementActivityIDDelete,
	"credential.revoked":      events.EntityManagementActivityIDDeactivate,
	"access.denied":           events.EntityManagementActivityIDRead,
}

// connections: Entity Management of the connection. Access denied is
// Medium.
func (c *common) connections() any {
	activity, ok := connectionActivities[c.ev.Action]
	if !ok {
		activity = events.EntityManagementActivityIDUpdate
	}
	if c.ev.Action == "access.denied" {
		c.severityID = events.SeverityIDMedium
	}
	return c.entityManagement(activity, c.entity("connection"))
}

// entity is the event's resource as a managed entity of the given type,
// by its ID. A key is named by its key identifier, which names no secret.
// Other resource identifiers, which may be email addresses or token
// prefixes, are left out; an entity with neither is named by its type.
func (c *common) entity(typ string) *objects.ManagedEntity {
	e := &objects.ManagedEntity{Type: typ}
	if c.ev.Resource.ID != uuid.Nil {
		e.UID = c.ev.Resource.ID.String()
	} else if typ == "key" {
		if id, ok := code(c.ev.Resource.Identifier); ok {
			e.UID = id
		}
	}
	if e.UID == "" {
		e.Name = typ
	}
	if c.metadata.TenantUID != "" {
		e.Org = &objects.Organization{UID: c.metadata.TenantUID}
	}
	return e
}

// scimAuthentication: a refused SCIM bearer token, Authentication,
// Logon, Failure, Medium. The token, when found, is the user by its ID.
func (c *common) scimAuthentication() any {
	if c.severityID < events.SeverityIDMedium {
		c.severityID = events.SeverityIDMedium
	}
	var u *objects.User
	if c.ev.Resource.ID != uuid.Nil {
		u = &objects.User{UID: c.ev.Resource.ID.String(), TypeID: objects.UserTypeIDService, Type: "scim_token"}
	}
	a := c.authentication(events.AuthenticationActivityIDLogon, u)
	a.protocol(events.AuthenticationAuthProtocolIDOther, "scim_bearer_token")
	return a
}

// scimTokenActivities maps SCIM token events to Entity Management
// activities.
var scimTokenActivities = map[string]int{
	"scim_token.issued":  events.EntityManagementActivityIDCreate,
	"scim_token.rotated": events.EntityManagementActivityIDUpdate,
	"scim_token.revoked": events.EntityManagementActivityIDDeactivate,
}

// scimToken: Entity Management of the organization's SCIM token, by its ID
// (never its prefix).
func (c *common) scimToken() any {
	return c.entityManagement(scimTokenActivities[c.ev.EventType], c.entity("scim_token"))
}

// signupActivities maps sign-up events to Entity Management activities.
var signupActivities = map[string]int{
	"signup_code.created":     events.EntityManagementActivityIDCreate,
	"signup_code.revoked":     events.EntityManagementActivityIDDeactivate,
	"signup_code.redeemed":    events.EntityManagementActivityIDUpdate,
	"signup_invite.created":   events.EntityManagementActivityIDCreate,
	"signup_invite.revoked":   events.EntityManagementActivityIDDeactivate,
	"signup_waitlist.invited": events.EntityManagementActivityIDCreate,
	"signup_allowance.set":    events.EntityManagementActivityIDUpdate,
}

// signup: Entity Management of the code, invite or allowance. An invite is
// identified by its email address, so it is recorded without an
// identifier; an allowance is the member's, by principal ID.
func (c *common) signup() any {
	var e *objects.ManagedEntity
	switch c.ev.EventType {
	case "signup_allowance.set":
		e = &objects.ManagedEntity{Type: "signup_allowance", User: user(c.ev.Resource.ID, "principal")}
		if e.User == nil {
			e.Name = "signup_allowance"
		}
	case "signup_invite.created", "signup_invite.revoked", "signup_waitlist.invited":
		e = &objects.ManagedEntity{Type: "signup_invite", Name: "signup_invite"}
	default:
		e = c.entity("signup_code")
	}
	return c.entityManagement(signupActivities[c.ev.EventType], e)
}

// managedPrincipalActivities maps the managed-principal events recorded
// as User Management of the managed principal.
var managedPrincipalActivities = map[string]int{
	"managed_principal.created":             events.UserManagementActivityIDCreate,
	"managed_principal.deleted":             events.UserManagementActivityIDDelete,
	"managed_principal.released":            events.UserManagementActivityIDUpdate,
	"managed_principal.email_attached":      events.UserManagementActivityIDUpdate,
	"managed_principal.email_verified":      events.UserManagementActivityIDUpdate,
	"managed_principal.claim_issued":        events.UserManagementActivityIDUpdate,
	"managed_principal.claim_redeemed":      events.UserManagementActivityIDUpdate,
	"managed_principal.manager_added":       events.UserManagementActivityIDUpdate,
	"managed_principal.manager_removed":     events.UserManagementActivityIDUpdate,
	"managed_principal.login_token_issued":  events.UserManagementActivityIDAddProgrammaticCredentials,
	"managed_principal.login_token_revoked": events.UserManagementActivityIDRemoveProgrammaticCredentials,
}

// managerInviteActivities maps manager-invite events, recorded as Entity
// Management of the invite.
var managerInviteActivities = map[string]int{
	"managed_principal.manager_invited":         events.EntityManagementActivityIDCreate,
	"managed_principal.manager_invite_accepted": events.EntityManagementActivityIDUpdate,
	"managed_principal.manager_invite_declined": events.EntityManagementActivityIDUpdate,
	"managed_principal.manager_invite_revoked":  events.EntityManagementActivityIDDeactivate,
}

// managedPrincipal maps the managed-principal events, or returns nil for
// one it does not know. Revoking a session or all access is
// Authentication, Logoff.
func (c *common) managedPrincipal() any {
	subject := user(c.ev.Resource.ID, "principal")
	switch c.ev.EventType {
	case "managed_principal.session_revoked", "managed_principal.all_revoked":
		a := c.authentication(events.AuthenticationActivityIDLogoff, subject)
		if sid := c.d.take("session_id"); sid != "" {
			a.Session = &objects.Session{UID: sid}
		}
		return a
	}
	if activity, ok := managerInviteActivities[c.ev.EventType]; ok {
		e := &objects.ManagedEntity{Type: "manager_invite", UID: c.d.take("invite_id"), User: subject}
		if e.UID == "" && e.User == nil {
			e.Name = "manager_invite"
		}
		return c.entityManagement(activity, e)
	}
	activity, ok := managedPrincipalActivities[c.ev.EventType]
	if !ok {
		return nil
	}
	if c.ev.EventType == "managed_principal.deleted" {
		c.severityID = max(c.severityID, events.SeverityIDLow)
	}
	if subject != nil {
		if credID := c.d.take("credential_id"); credID != "" {
			subject.ProgrammaticCredentials = []objects.ProgrammaticCredential{{UID: credID, Type: "login_token"}}
		}
	}
	return c.userManagement(activity, subject)
}
