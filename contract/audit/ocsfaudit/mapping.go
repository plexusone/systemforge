package ocsfaudit

import (
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"

	"github.com/plexusone/systemforge/contract/audit"
)

// The event classes are the generated ones with cloud and osint made
// optional: both are required only by the cloud and osint profiles, which
// these events do not declare, and the generated structs would otherwise
// write them as null. The outer field shadows the embedded one in JSON.
type (
	authentication struct {
		events.Authentication
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
	userManagement struct {
		events.UserManagement
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
	groupManagement struct {
		events.GroupManagement
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
	entityManagement struct {
		events.EntityManagement
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
	applicationLifecycle struct {
		events.ApplicationLifecycle
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
	baseEvent struct {
		events.BaseEvent
		Cloud *objects.Cloud  `json:"cloud,omitempty"`
		OSINT []objects.OSINT `json:"osint,omitempty"`
	}
)

// Base Event's classification captions; the generated caption maps cover
// concrete classes and categories only.
const (
	baseEventClassName    = "Base Event"
	baseEventCategoryName = "Uncategorized"
)

// maxUserAgent bounds the User-Agent copied into an event.
const maxUserAgent = 512

// unknownUser stands for the user of an authentication or account event
// whose principal is not known, such as a refused sign-in: those classes
// require a user, and a user needs a name or an ID.
func unknownUser() *objects.User {
	return &objects.User{Name: "unknown", TypeID: objects.UserTypeIDUnknown, Type: objects.UserTypeIDCaptions[objects.UserTypeIDUnknown]}
}

// common holds what every class carries, worked out once per event.
type common struct {
	ev           *audit.Event
	d            details
	metadata     *objects.Metadata
	time         int64
	severityID   int
	statusID     int
	statusDetail string
	statusCode   string
	actor        *objects.Actor
	src          *objects.NetworkEndpoint
	http         *objects.HTTPRequest
	message      string
	service      *objects.Service
}

func (c *common) severity() string { return events.SeverityIDCaptions[c.severityID] }

func (c *common) status() string { return events.StatusIDCaptions[c.statusID] }

func (c *common) isAlert() *bool {
	if c.severityID >= events.SeverityIDHigh {
		t := true
		return &t
	}
	return nil
}

func (c *common) unmapped() map[string]any {
	if len(c.d) == 0 {
		return nil
	}
	return map[string]any(c.d)
}

// mapper turns audit events into OCSF events.
type mapper struct {
	product  objects.Product
	reporter *objects.Reporter
	now      func() time.Time
	newUID   func() string
}

// toOCSF returns the OCSF event for ev, of the class its event type maps
// to, or a Base Event for an event type it does not know.
func (m *mapper) toOCSF(ev *audit.Event) any {
	c := m.common(ev)
	switch ev.EventType {
	case "systemauth.sign_in":
		return c.signIn()
	case "systemauth.sign_out":
		return c.signOut()
	case "systemauth.token.refused", "systemauth.refresh_token.reuse", "systemauth.authorization_code.reuse":
		return c.tokenRequest()
	case "systemauth.token.revoked", "systemauth.token_family.revoked":
		return c.tokenRevocation()
	case "systemauth.email_verification.sent", "systemauth.email.verified",
		"systemauth.email_change.requested", "systemauth.email_change.cancelled", "systemauth.email.changed":
		return c.email()
	case "systemauth.signing_key.loaded", "systemauth.production.waiver":
		return c.startup()
	case "organization.membership":
		return c.membership()
	case "principal.platform_admin":
		return c.platformAdmin()
	case "service_account":
		return c.serviceAccount()
	case "keys":
		return c.keys()
	case "connections":
		return c.connections()
	case "scim_token.authentication_failed":
		return c.scimAuthentication()
	case "scim_token.issued", "scim_token.rotated", "scim_token.revoked":
		return c.scimToken()
	case "signup_code.created", "signup_code.revoked", "signup_code.redeemed",
		"signup_invite.created", "signup_invite.revoked", "signup_waitlist.invited", "signup_allowance.set":
		return c.signup()
	}
	if strings.HasPrefix(ev.EventType, "managed_principal.") {
		if v := c.managedPrincipal(); v != nil {
			return v
		}
	}
	return c.base()
}

func (m *mapper) common(ev *audit.Event) *common {
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = m.now()
	}
	uid := m.newUID()
	if ev.ID != uuid.Nil {
		uid = ev.ID.String()
	}
	product := m.product
	md := &objects.Metadata{
		Version:        events.SchemaVersion,
		Product:        &product,
		UID:            uid,
		CorrelationUID: ev.Context.RequestID,
		EventCode:      ev.EventType,
		Reporter:       m.reporter,
	}
	if !codePattern.MatchString(md.CorrelationUID) {
		md.CorrelationUID = ""
	}
	if !codePattern.MatchString(md.EventCode) {
		md.EventCode = ""
	}
	d := allowedDetails(ev.EventType, ev.Details)
	if ev.Context.TenantID != nil && *ev.Context.TenantID != uuid.Nil {
		md.TenantUID = ev.Context.TenantID.String()
	} else if org := d.get("organization_id"); org != "" {
		md.TenantUID = org
	}
	c := &common{
		ev:         ev,
		d:          d,
		metadata:   md,
		time:       ts.UnixMilli(),
		severityID: events.SeverityIDInformational,
		actor:      actorOf(ev.Actor),
		service:    &objects.Service{Name: m.product.Name, Version: m.product.Version},
	}
	switch ev.Outcome {
	case audit.OutcomeSuccess:
		c.statusID = events.StatusIDSuccess
	case audit.OutcomeFailure:
		c.statusID = events.StatusIDFailure
		c.severityID = events.SeverityIDLow
	}
	c.statusDetail = d.take("reason")
	c.statusCode = d.take("error")
	if addr, err := netip.ParseAddr(ev.Context.ClientIP); err == nil {
		c.src = &objects.NetworkEndpoint{IP: addr.Unmap().String()}
	}
	if ua := ev.Context.UserAgent; ua != "" {
		if len(ua) > maxUserAgent {
			ua = ua[:maxUserAgent]
		}
		c.http = &objects.HTTPRequest{UserAgent: strings.ToValidUTF8(ua, "")}
	}
	c.message = message(ev)
	return c
}

// message describes the event from its type, action and outcome, each
// only when it is a code.
func message(ev *audit.Event) string {
	var parts []string
	for _, s := range []string{ev.EventType, ev.Action, ev.Outcome} {
		if codePattern.MatchString(s) {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// User types of actors and subjects.
var userTypes = map[string]int{
	"human":           objects.UserTypeIDUser,
	"principal":       objects.UserTypeIDUser,
	"user":            objects.UserTypeIDUser,
	"service_account": objects.UserTypeIDService,
}

// user returns the OCSF user for a principal ID of the given audit actor
// type, or nil for no ID.
func user(id uuid.UUID, actorType string) *objects.User {
	if id == uuid.Nil {
		return nil
	}
	u := &objects.User{UID: id.String()}
	if tid, ok := userTypes[actorType]; ok {
		u.TypeID, u.Type = tid, objects.UserTypeIDCaptions[tid]
	} else if actorType != "" && codePattern.MatchString(actorType) {
		u.TypeID, u.Type = objects.UserTypeIDOther, actorType
	}
	return u
}

// clientUser is an OAuth client as the subject of a client-credentials
// token request.
func clientUser(clientID string) *objects.User {
	return &objects.User{UID: clientID, TypeID: objects.UserTypeIDService, Type: objects.UserTypeIDCaptions[objects.UserTypeIDService]}
}

// actorOf maps the audit actor by ID only. An OAuth client is named by
// its client ID and a component of SystemForge by its name; any other
// identifier, which may be an email address, is left out.
func actorOf(a audit.Actor) *objects.Actor {
	out := &objects.Actor{User: user(a.ID, a.Type)}
	switch a.Type {
	case "application":
		if id, ok := code(a.Identifier); ok {
			out.Application = &objects.Application{UID: id, Type: "oauth_client"}
		}
	case "service":
		if name, ok := code(a.Identifier); ok {
			out.Application = &objects.Application{Name: name}
		}
	}
	if out.User == nil && out.Application == nil {
		return nil
	}
	return out
}

// subject is the principal an account event is about: the resource when
// it is a principal, else the actor.
func (c *common) subject() *objects.User {
	if c.ev.Resource.ID != uuid.Nil && (c.ev.Resource.Type == "principal" || c.ev.Resource.Type == "membership") {
		return user(c.ev.Resource.ID, "principal")
	}
	return user(c.ev.Actor.ID, c.ev.Actor.Type)
}

func orUnknown(u *objects.User) *objects.User {
	if u == nil {
		return unknownUser()
	}
	return u
}

// Class builders. Each fills the common attributes; the caller adds the
// class's own.

func (c *common) authentication(activity int, u *objects.User) *authentication {
	return &authentication{Authentication: events.Authentication{
		ActivityID:   activity,
		ActivityName: events.AuthenticationActivityIDCaptions[activity],
		CategoryUID:  events.CategoryUIDIAM,
		CategoryName: events.CategoryCaptions[events.CategoryUIDIAM],
		ClassUID:     events.ClassUIDAuthentication,
		ClassName:    events.ClassCaptions[events.ClassUIDAuthentication],
		TypeUID:      int64(events.ClassUIDAuthentication)*100 + int64(activity),
		TypeName:     events.ClassCaptions[events.ClassUIDAuthentication] + ": " + events.AuthenticationActivityIDCaptions[activity],
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		SrcEndpoint:  c.src,
		HTTPRequest:  c.http,
		Service:      c.service,
		User:         orUnknown(u),
		Unmapped:     c.unmapped(),
	}}
}

func (c *common) userManagement(activity int, u *objects.User) *userManagement {
	return &userManagement{UserManagement: events.UserManagement{
		ActivityID:   activity,
		ActivityName: events.UserManagementActivityIDCaptions[activity],
		CategoryUID:  events.CategoryUIDIAM,
		CategoryName: events.CategoryCaptions[events.CategoryUIDIAM],
		ClassUID:     events.ClassUIDUserManagement,
		ClassName:    events.ClassCaptions[events.ClassUIDUserManagement],
		TypeUID:      int64(events.ClassUIDUserManagement)*100 + int64(activity),
		TypeName:     events.ClassCaptions[events.ClassUIDUserManagement] + ": " + events.UserManagementActivityIDCaptions[activity],
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		SrcEndpoint:  c.src,
		HTTPRequest:  c.http,
		User:         orUnknown(u),
		Unmapped:     c.unmapped(),
	}}
}

func (c *common) groupManagement(activity int, g *objects.Group, u *objects.User) *groupManagement {
	var users []objects.User
	if u != nil {
		users = []objects.User{*u}
	}
	return &groupManagement{GroupManagement: events.GroupManagement{
		ActivityID:   activity,
		ActivityName: events.GroupManagementActivityIDCaptions[activity],
		CategoryUID:  events.CategoryUIDIAM,
		CategoryName: events.CategoryCaptions[events.CategoryUIDIAM],
		ClassUID:     events.ClassUIDGroupManagement,
		ClassName:    events.ClassCaptions[events.ClassUIDGroupManagement],
		TypeUID:      int64(events.ClassUIDGroupManagement)*100 + int64(activity),
		TypeName:     events.ClassCaptions[events.ClassUIDGroupManagement] + ": " + events.GroupManagementActivityIDCaptions[activity],
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		SrcEndpoint:  c.src,
		HTTPRequest:  c.http,
		Group:        g,
		Users:        users,
		Unmapped:     c.unmapped(),
	}}
}

func (c *common) entityManagement(activity int, e *objects.ManagedEntity) *entityManagement {
	return &entityManagement{EntityManagement: events.EntityManagement{
		ActivityID:   activity,
		ActivityName: events.EntityManagementActivityIDCaptions[activity],
		CategoryUID:  events.CategoryUIDIAM,
		CategoryName: events.CategoryCaptions[events.CategoryUIDIAM],
		ClassUID:     events.ClassUIDEntityManagement,
		ClassName:    events.ClassCaptions[events.ClassUIDEntityManagement],
		TypeUID:      int64(events.ClassUIDEntityManagement)*100 + int64(activity),
		TypeName:     events.ClassCaptions[events.ClassUIDEntityManagement] + ": " + events.EntityManagementActivityIDCaptions[activity],
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		SrcEndpoint:  c.src,
		HTTPRequest:  c.http,
		Entity:       e,
		Unmapped:     c.unmapped(),
	}}
}

func (c *common) applicationLifecycle(activity int) *applicationLifecycle {
	app := &objects.Application{Name: c.metadata.Product.Name, Version: c.metadata.Product.Version}
	return &applicationLifecycle{ApplicationLifecycle: events.ApplicationLifecycle{
		ActivityID:   activity,
		ActivityName: events.ApplicationLifecycleActivityIDCaptions[activity],
		CategoryUID:  events.CategoryUIDApplication,
		CategoryName: events.CategoryCaptions[events.CategoryUIDApplication],
		ClassUID:     events.ClassUIDApplicationLifecycle,
		ClassName:    events.ClassCaptions[events.ClassUIDApplicationLifecycle],
		TypeUID:      int64(events.ClassUIDApplicationLifecycle)*100 + int64(activity),
		TypeName:     events.ClassCaptions[events.ClassUIDApplicationLifecycle] + ": " + events.ApplicationLifecycleActivityIDCaptions[activity],
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		Application:  app,
		Unmapped:     c.unmapped(),
	}}
}

// base is the Base Event, activity Other, of an event type this package
// does not map. Of its details none are kept: there is no allowlist for
// them. The resource is kept by type and ID.
func (c *common) base() *baseEvent {
	activityName := events.BaseEventActivityIDCaptions[events.BaseEventActivityIDOther]
	if codePattern.MatchString(c.ev.Action) {
		activityName = c.ev.Action
	}
	unmapped := c.unmapped()
	if c.ev.Resource.ID != uuid.Nil || codePattern.MatchString(c.ev.Resource.Type) {
		if unmapped == nil {
			unmapped = map[string]any{}
		}
		if c.ev.Resource.ID != uuid.Nil {
			unmapped["resource_uid"] = c.ev.Resource.ID.String()
		}
		if codePattern.MatchString(c.ev.Resource.Type) {
			unmapped["resource_type"] = c.ev.Resource.Type
		}
	}
	return &baseEvent{BaseEvent: events.BaseEvent{
		ActivityID:   events.BaseEventActivityIDOther,
		ActivityName: activityName,
		CategoryUID:  0,
		CategoryName: baseEventCategoryName,
		ClassUID:     0,
		ClassName:    baseEventClassName,
		TypeUID:      events.BaseEventActivityIDOther,
		TypeName:     baseEventClassName + ": " + activityName,
		Metadata:     c.metadata,
		Time:         c.time,
		SeverityID:   c.severityID,
		Severity:     c.severity(),
		StatusID:     c.statusID,
		Status:       c.status(),
		StatusDetail: c.statusDetail,
		StatusCode:   c.statusCode,
		IsAlert:      c.isAlert(),
		Message:      c.message,
		Actor:        c.actor,
		Unmapped:     unmapped,
	}}
}
