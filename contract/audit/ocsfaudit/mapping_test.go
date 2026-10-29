package ocsfaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/grokify/ocsf-schema-go/ocsf/events"
	"github.com/grokify/ocsf-schema-go/ocsf/objects"
	"github.com/grokify/ocsf-schema-go/ocsf/ocsfdata"
	"github.com/grokify/ocsf-schema-go/validate"

	"github.com/plexusone/systemforge/contract/audit"
)

var (
	principalID = uuid.MustParse("8f8a4d0e-3c55-4b8e-9d1e-0a6f1d2c3b4a")
	resourceID  = uuid.MustParse("1b2c3d4e-5f60-4718-8a9b-0c1d2e3f4a5b")
	orgID       = uuid.MustParse("6a7b8c9d-0e1f-4a2b-8c3d-4e5f6a7b8c9d")
	otherID     = uuid.MustParse("2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f")
)

// Secrets and personal data the cases put where callers might: none may
// reach the OCSF output.
const (
	leakEmail   = "alice.leak@example.com"
	leakSession = "session-token-must-not-appear"
	leakPrefix  = "scim_prefix_must_not_appear"
	leakLabel   = "Label naming Alice"
	leakRisk    = "risk text that is not a code"
	leakToken   = "login-token-prefix-must-not-appear" //nolint:gosec // G101: test fixture
)

// mappingCase is one representative event and the OCSF classification it
// must get.
type mappingCase struct {
	name     string
	ev       audit.Event
	class    int
	activity int
	severity int
}

func evt(eventType, action, outcome string, details map[string]any) audit.Event {
	tenant := orgID
	return audit.Event{
		EventType: eventType,
		Action:    action,
		Outcome:   outcome,
		Actor:     audit.Actor{ID: principalID, Type: "human", Identifier: leakEmail},
		Resource:  audit.Resource{Type: "principal", ID: resourceID, Identifier: leakEmail},
		Context: audit.Context{
			TenantID: &tenant, SessionID: leakSession, ClientIP: "203.0.113.7",
			UserAgent: "Mozilla/5.0 (test)", RequestID: "host/abc-000001",
		},
		Timestamp: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		Details:   details,
	}
}

func withActor(ev audit.Event, a audit.Actor) audit.Event       { ev.Actor = a; return ev }
func withResource(ev audit.Event, r audit.Resource) audit.Event { ev.Resource = r; return ev }

const (
	auth   = events.ClassUIDAuthentication
	userMg = events.ClassUIDUserManagement
	groupM = events.ClassUIDGroupManagement
	entity = events.ClassUIDEntityManagement
	appLC  = events.ClassUIDApplicationLifecycle
	info   = events.SeverityIDInformational
	low    = events.SeverityIDLow
	medium = events.SeverityIDMedium
	high   = events.SeverityIDHigh
)

func mappingCases() []mappingCase {
	client := audit.Actor{Type: "application", Identifier: "spa"}
	service := audit.Actor{Type: "service", Identifier: "systemauth"}
	ok, fail := audit.OutcomeSuccess, audit.OutcomeFailure
	return []mappingCase{
		{"sign_in success", withActor(evt("systemauth.sign_in", "sign_in", ok, map[string]any{"method": "github", "client_id": "spa"}), audit.Actor{ID: principalID, Type: "principal"}), auth, events.AuthenticationActivityIDLogon, info},
		{"sign_in failure", withActor(evt("systemauth.sign_in", "sign_in", fail, map[string]any{"method": "login_token", "reason": "invalid_state"}), audit.Actor{Type: "principal"}), auth, events.AuthenticationActivityIDLogon, low},
		{"sign_out", evt("systemauth.sign_out", "sign_out", ok, map[string]any{"method": "google", "tokens_revoked": true}), auth, events.AuthenticationActivityIDLogoff, info},
		{"token refused", withActor(evt("systemauth.token.refused", "issue_token", fail, map[string]any{"grant_type": "client_credentials", "client_id": "svc", "reason": "request_invalid", "error": "invalid_client"}), client), auth, events.AuthenticationActivityIDLogon, low},
		{"refresh token reuse", withActor(evt("systemauth.refresh_token.reuse", "redeem_refresh_token", fail, map[string]any{"grant_type": "refresh_token", "client_id": "spa", "family_revoked": true}), client), auth, events.AuthenticationActivityIDLogon, high},
		{"authorization code reuse", withActor(evt("systemauth.authorization_code.reuse", "redeem_authorization_code", fail, map[string]any{"grant_type": "authorization_code", "client_id": "spa", "family_revoked": true}), client), auth, events.AuthenticationActivityIDLogon, high},
		{"token revoked", withActor(evt("systemauth.token.revoked", "revoke", ok, map[string]any{"client_id": "spa", "token_type_hint": "access_token"}), client), auth, events.AuthenticationActivityIDLogoff, info},
		{"token revoke failed", withActor(evt("systemauth.token.revoked", "revoke", fail, map[string]any{"client_id": "spa", "error": "invalid_client"}), client), auth, events.AuthenticationActivityIDLogoff, low},
		{"token family revoked", withResource(withActor(evt("systemauth.token_family.revoked", "revoke", ok, map[string]any{"reason": "principal_inactive", "subject": principalID.String(), "client_id": "spa"}), service), audit.Resource{Type: "token_family", Identifier: "request-id"}), auth, events.AuthenticationActivityIDLogoff, info},
		{"verification sent sign-in", withActor(evt("systemauth.email_verification.sent", "send_verification", ok, map[string]any{"purpose": "verify_email", "sent": true, "email": leakEmail}), audit.Actor{Type: "principal"}), auth, events.AuthenticationActivityIDPreauth, info},
		{"verification sent change", evt("systemauth.email_verification.sent", "send_verification", ok, map[string]any{"purpose": "email_change", "sent": false}), userMg, events.UserManagementActivityIDUpdate, info},
		{"email verified sign-in", withActor(evt("systemauth.email.verified", "verify_email", ok, map[string]any{"purpose": "verify_email", "method": "github"}), audit.Actor{Type: "principal"}), auth, events.AuthenticationActivityIDPreauth, info},
		{"email verified change", evt("systemauth.email.verified", "verify_email", ok, map[string]any{"purpose": "email_change"}), userMg, events.UserManagementActivityIDUpdate, info},
		{"email change requested", evt("systemauth.email_change.requested", "request_email_change", ok, nil), userMg, events.UserManagementActivityIDUpdate, info},
		{"email change cancelled", evt("systemauth.email_change.cancelled", "cancel_email_change", ok, nil), userMg, events.UserManagementActivityIDUpdate, info},
		{"email changed", evt("systemauth.email.changed", "change_email", ok, map[string]any{"old_email": leakEmail, "new_email": leakEmail}), userMg, events.UserManagementActivityIDUpdate, info},
		{"signing key loaded", withResource(withActor(evt("systemauth.signing_key.loaded", "load", ok, map[string]any{"key_id": "kid-2026", "verification_key_ids": []string{"kid-2025", "kid-2026"}, "ephemeral": false}), service), audit.Resource{Type: "signing_key", Identifier: "kid-2026"}), appLC, events.ApplicationLifecycleActivityIDStart, info},
		{"production waiver", withResource(withActor(evt("systemauth.production.waiver", "waive", ok, map[string]any{"check": "dpop.single_instance", "setting": "dpop.single_instance", "risk": leakRisk}), service), audit.Resource{Type: "production_check", Identifier: "dpop.single_instance"}), appLC, events.ApplicationLifecycleActivityIDStart, medium},
		{"membership added", withResource(evt("organization.membership", "added", ok, map[string]any{"organization_id": orgID.String(), "principal_id": resourceID.String(), "role": "member"}), audit.Resource{Type: "membership", ID: resourceID}), groupM, events.GroupManagementActivityIDAddUser, info},
		{"membership updated", withResource(evt("organization.membership", "updated", ok, map[string]any{"organization_id": orgID.String(), "principal_id": resourceID.String(), "role": "admin", "old_role": "member", "was_active": true, "active": true}), audit.Resource{Type: "membership", ID: resourceID}), groupM, events.GroupManagementActivityIDUpdate, info},
		{"membership removed", withResource(evt("organization.membership", "removed", ok, map[string]any{"organization_id": orgID.String(), "principal_id": resourceID.String(), "role": "member"}), audit.Resource{Type: "membership", ID: resourceID}), groupM, events.GroupManagementActivityIDRemoveUser, info},
		{"ownership transferred", withResource(evt("organization.membership", "ownership_transferred", ok, map[string]any{"organization_id": orgID.String(), "principal_id": resourceID.String(), "role": "owner", "previous_owner_id": otherID.String(), "previous_owner_role": "admin"}), audit.Resource{Type: "membership", ID: resourceID}), groupM, events.GroupManagementActivityIDUpdate, medium},
		{"platform admin granted", evt("principal.platform_admin", "granted", ok, nil), userMg, events.UserManagementActivityIDAssignPrivileges, high},
		{"platform admin revoked", evt("principal.platform_admin", "revoked", ok, nil), userMg, events.UserManagementActivityIDRemovePrivileges, info},
		{"service account created", withResource(evt("service_account", "created", ok, map[string]any{"identifier": leakEmail, "organization_id": orgID.String()}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDCreate, info},
		{"service account disabled", withResource(evt("service_account", "disabled", ok, nil), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDDisable, info},
		{"service account enabled", withResource(evt("service_account", "enabled", ok, nil), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDEnable, info},
		{"service account deleted", withResource(evt("service_account", "deleted", ok, map[string]any{"identifier": leakEmail}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDDelete, info},
		{"service account key added", withResource(evt("service_account", "key_added", ok, map[string]any{"key_id": "sa-key-1", "algorithm": "ES256", "expires_at": "2027-01-01T00:00:00Z", "private_key": "-----BEGIN PRIVATE KEY-----"}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDAddProgrammaticCredentials, info},
		{"service account key revoked", withResource(evt("service_account", "key_revoked", ok, map[string]any{"key_id": "sa-key-1", "reason": "rotated"}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDRemoveProgrammaticCredentials, info},
		{"service account role granted", withResource(evt("service_account", "role_granted", ok, map[string]any{"application": "billing", "role": "reader", "organization_id": orgID.String()}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDAssignRoles, info},
		{"service account role removed", withResource(evt("service_account", "role_removed", ok, map[string]any{"application": "billing", "organization_id": orgID.String()}), audit.Resource{Type: "service_account", ID: resourceID}), userMg, events.UserManagementActivityIDRemoveRoles, info},
		{"key created", withResource(withActor(evt("keys", "key.created", ok, map[string]any{"purpose": "tokens", "outcome": "success", "event_id": "evt-1"}), audit.Actor{Type: "service", Identifier: "keyforge"}), audit.Resource{Type: "key", Identifier: "kek-1/v1"}), entity, events.EntityManagementActivityIDCreate, info},
		{"key compromised", withResource(withActor(evt("keys", "key.compromised", ok, map[string]any{"purpose": "tokens", "reason": "operator said Alice leaked it"}), audit.Actor{Type: "human", Identifier: leakEmail}), audit.Resource{Type: "key", Identifier: "kek-1/v1"}), entity, events.EntityManagementActivityIDUpdate, high},
		{"key guard denied", withResource(evt("keys", "guard.denied", fail, map[string]any{"purpose": "tokens", "outcome": "denied"}), audit.Resource{Type: "key", Identifier: "tokens"}), entity, events.EntityManagementActivityIDRead, medium},
		{"connection created", withResource(evt("connections", "connection.created", ok, map[string]any{"provider": "github", "on_behalf_of": "user:" + leakEmail, "access_token": leakSession}), audit.Resource{Type: "connection", ID: resourceID, Identifier: resourceID.String()}), entity, events.EntityManagementActivityIDCreate, info},
		{"connection access denied", withResource(evt("connections", "access.denied", fail, map[string]any{"provider": "github", "reason": "not_granted"}), audit.Resource{Type: "connection", ID: resourceID}), entity, events.EntityManagementActivityIDRead, medium},
		{"scim token issued", withResource(evt("scim_token.issued", "issue", ok, map[string]any{"generation": 1, "revoked": []string{}}), audit.Resource{Type: "scim_token", ID: resourceID, Identifier: leakPrefix}), entity, events.EntityManagementActivityIDCreate, info},
		{"scim token rotated", withResource(evt("scim_token.rotated", "rotate", ok, map[string]any{"generation": 2, "revoked": []string{otherID.String()}}), audit.Resource{Type: "scim_token", ID: resourceID, Identifier: leakPrefix}), entity, events.EntityManagementActivityIDUpdate, info},
		{"scim token revoked", withResource(evt("scim_token.revoked", "revoke", ok, map[string]any{"generation": 2}), audit.Resource{Type: "scim_token", ID: resourceID, Identifier: leakPrefix}), entity, events.EntityManagementActivityIDDeactivate, info},
		{"scim token authentication failed", withResource(withActor(evt("scim_token.authentication_failed", "authenticate", fail, map[string]any{"reason": "revoked"}), audit.Actor{}), audit.Resource{Type: "scim_token", ID: resourceID, Identifier: leakPrefix}), auth, events.AuthenticationActivityIDLogon, medium},
		{"scim token unknown", withResource(withActor(evt("scim_token.authentication_failed", "authenticate", fail, map[string]any{"reason": "unknown_token"}), audit.Actor{}), audit.Resource{Type: "scim_token"}), auth, events.AuthenticationActivityIDLogon, medium},
		{"signup code created", withResource(evt("signup_code.created", "create", ok, map[string]any{"kind": "batch", "label": leakLabel, "max_uses": 10}), audit.Resource{Type: "signup_code", ID: resourceID}), entity, events.EntityManagementActivityIDCreate, info},
		{"signup code revoked", withResource(evt("signup_code.revoked", "revoke", ok, nil), audit.Resource{Type: "signup_code", ID: resourceID}), entity, events.EntityManagementActivityIDDeactivate, info},
		{"signup code redeemed", withResource(evt("signup_code.redeemed", "redeem", ok, map[string]any{"provider": "github"}), audit.Resource{Type: "signup_code", ID: resourceID}), entity, events.EntityManagementActivityIDUpdate, info},
		{"signup invite created", withResource(evt("signup_invite.created", "create", ok, nil), audit.Resource{Type: "signup_invite", Identifier: leakEmail}), entity, events.EntityManagementActivityIDCreate, info},
		{"signup invite revoked", withResource(evt("signup_invite.revoked", "revoke", ok, nil), audit.Resource{Type: "signup_invite", Identifier: leakEmail}), entity, events.EntityManagementActivityIDDeactivate, info},
		{"signup waitlist invited", withResource(evt("signup_waitlist.invited", "invite", ok, nil), audit.Resource{Type: "signup_waitlist", Identifier: leakEmail}), entity, events.EntityManagementActivityIDCreate, info},
		{"signup allowance set", evt("signup_allowance.set", "set", ok, map[string]any{"granted": 3}), entity, events.EntityManagementActivityIDUpdate, info},
		{"managed created", evt("managed_principal.created", "create", ok, map[string]any{"client_id": "classroom", "managers": []map[string]string{{"principal_id": otherID.String(), "role": "guardian"}}, "has_email": false}), userMg, events.UserManagementActivityIDCreate, info},
		{"managed deleted", evt("managed_principal.deleted", "delete", ok, map[string]any{"credentials": 2, "login_sessions": 1, "relationships": 1}), userMg, events.UserManagementActivityIDDelete, low},
		{"managed released", evt("managed_principal.released", "release", ok, map[string]any{"managers": []map[string]string{{"principal_id": otherID.String(), "role": "guardian"}}}), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed email attached", evt("managed_principal.email_attached", "attach_email", ok, nil), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed email verified", evt("managed_principal.email_verified", "verify_email", ok, nil), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed claim issued", evt("managed_principal.claim_issued", "issue_claim", ok, map[string]any{"claim_id": otherID.String(), "expires_at": time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC), "code": leakToken}), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed claim redeemed", evt("managed_principal.claim_redeemed", "redeem_claim", ok, map[string]any{"manager_principal_id": otherID.String(), "role": "guardian"}), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed manager added", evt("managed_principal.manager_added", "add_manager", ok, map[string]any{"manager_principal_id": otherID.String(), "role": "educator"}), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed manager removed", evt("managed_principal.manager_removed", "remove_manager", ok, map[string]any{"manager_principal_id": otherID.String(), "role": "educator"}), userMg, events.UserManagementActivityIDUpdate, info},
		{"managed manager invited", evt("managed_principal.manager_invited", "invite_manager", ok, map[string]any{"invite_id": otherID.String(), "role": "guardian", "client_id": "classroom", "expires_at": time.Date(2026, 9, 8, 0, 0, 0, 0, time.UTC)}), entity, events.EntityManagementActivityIDCreate, info},
		{"managed manager invite accepted", evt("managed_principal.manager_invite_accepted", "accept_manager_invite", ok, map[string]any{"manager_principal_id": otherID.String(), "role": "guardian"}), entity, events.EntityManagementActivityIDUpdate, info},
		{"managed manager invite declined", evt("managed_principal.manager_invite_declined", "decline_manager_invite", ok, map[string]any{"invite_id": otherID.String(), "manager_principal_id": otherID.String(), "role": "guardian"}), entity, events.EntityManagementActivityIDUpdate, info},
		{"managed manager invite revoked", evt("managed_principal.manager_invite_revoked", "revoke_manager_invite", ok, map[string]any{"invite_id": otherID.String()}), entity, events.EntityManagementActivityIDDeactivate, info},
		{"managed login token issued", evt("managed_principal.login_token_issued", "issue_login_token", ok, map[string]any{"client_id": "classroom", "credential_id": otherID.String(), "prefix": leakToken, "expires_at": time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}), userMg, events.UserManagementActivityIDAddProgrammaticCredentials, info},
		{"managed login token revoked", evt("managed_principal.login_token_revoked", "revoke_login_token", ok, map[string]any{"credential_id": otherID.String()}), userMg, events.UserManagementActivityIDRemoveProgrammaticCredentials, info},
		{"managed session revoked", evt("managed_principal.session_revoked", "revoke_session", ok, map[string]any{"kind": "login_session", "session_id": otherID.String()}), auth, events.AuthenticationActivityIDLogoff, info},
		{"managed all revoked", evt("managed_principal.all_revoked", "revoke_all", ok, map[string]any{"login_tokens": 1, "login_sessions": 2, "oauth_tokens": 3, "principal_tokens": 0}), auth, events.AuthenticationActivityIDLogoff, info},
		{"unknown event type", evt("future.thing", "did_something", ok, map[string]any{"email": leakEmail}), 0, events.BaseEventActivityIDOther, info},
		{"unknown failure", evt("managed_principal.future_action", "", fail, nil), 0, events.BaseEventActivityIDOther, low},
	}
}

func newTestMapper() *mapper {
	return &mapper{
		product:  testProduct(),
		reporter: nil,
		now:      func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) },
		newUID:   func() string { return "generated-uid" },
	}
}

// strictValidator reports unknown attributes as errors; deprecation
// warnings are checked separately so no case uses a deprecated attribute.
func strictValidator() *validate.Validator {
	return validate.New(ocsfdata.MustSchema(), validate.WithUnknownAttributes(validate.UnknownError), validate.WithDeprecatedWarnings(true))
}

// validateOCSF validates one event against the embedded schema, strictly:
// every issue, warnings included, fails the test.
func validateOCSF(t *testing.T, v *validate.Validator, data []byte) {
	t.Helper()
	res := v.ValidateEvent(data)
	for _, issue := range res.Issues {
		t.Errorf("%s", issue)
	}
	if t.Failed() {
		t.Logf("event: %s", data)
	}
}

// TestEveryEventTypeIsValidOCSF maps a representative event of every
// event type, with success and failure where the outcome matters, and
// validates the result against the embedded OCSF schema.
func TestEveryEventTypeIsValidOCSF(t *testing.T) {
	v := strictValidator()
	m := newTestMapper()
	for _, tc := range mappingCases() {
		t.Run(tc.name, func(t *testing.T) {
			ev := tc.ev
			data, err := json.Marshal(m.toOCSF(&ev))
			if err != nil {
				t.Fatal(err)
			}
			validateOCSF(t, v, data)
			var got struct {
				ClassUID   int   `json:"class_uid"`
				ActivityID int   `json:"activity_id"`
				SeverityID int   `json:"severity_id"`
				TypeUID    int64 `json:"type_uid"`
				StatusID   int   `json:"status_id"`
				Time       int64 `json:"time"`
				Metadata   struct {
					UID            string `json:"uid"`
					CorrelationUID string `json:"correlation_uid"`
					TenantUID      string `json:"tenant_uid"`
					EventCode      string `json:"event_code"`
					Version        string `json:"version"`
				} `json:"metadata"`
			}
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if got.ClassUID != tc.class || got.ActivityID != tc.activity || got.SeverityID != tc.severity {
				t.Errorf("class/activity/severity = %d/%d/%d, want %d/%d/%d", got.ClassUID, got.ActivityID, got.SeverityID, tc.class, tc.activity, tc.severity)
			}
			if got.TypeUID != int64(tc.class)*100+int64(tc.activity) {
				t.Errorf("type_uid = %d", got.TypeUID)
			}
			wantStatus := map[string]int{audit.OutcomeSuccess: events.StatusIDSuccess, audit.OutcomeFailure: events.StatusIDFailure}[ev.Outcome]
			if got.StatusID != wantStatus {
				t.Errorf("status_id = %d, want %d", got.StatusID, wantStatus)
			}
			if got.Time != ev.Timestamp.UnixMilli() {
				t.Errorf("time = %d", got.Time)
			}
			md := got.Metadata
			if md.UID != "generated-uid" || md.CorrelationUID != "host/abc-000001" || md.TenantUID != orgID.String() ||
				md.EventCode != ev.EventType || md.Version != events.SchemaVersion {
				t.Errorf("metadata: %+v", md)
			}
			for _, leak := range []string{leakEmail, leakSession, leakPrefix, leakLabel, leakRisk, leakToken, "Alice", "PRIVATE KEY"} {
				if strings.Contains(string(data), leak) {
					t.Errorf("output carries %q: %s", leak, data)
				}
			}
		})
	}
}

// TestCasesCoverEveryAllowlist keeps the allowlists and the cases in step:
// every event type with an allowlist has a case.
func TestCasesCoverEveryAllowlist(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range mappingCases() {
		covered[tc.ev.EventType] = true
	}
	for eventType := range allowed {
		if !covered[eventType] {
			t.Errorf("no case for %s", eventType)
		}
	}
}

func TestCommonFields(t *testing.T) {
	m := newTestMapper()
	m.reporter = reporter("prod-eu")
	ev := evt("systemauth.sign_in", "sign_in", audit.OutcomeSuccess, map[string]any{"method": "github"})
	ev.ID = otherID
	ev.Actor = audit.Actor{ID: principalID, Type: "principal"}
	data, err := json.Marshal(m.toOCSF(&ev))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	path := func(keys ...string) any {
		var cur any = got
		for _, k := range keys {
			mm, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur = mm[k]
		}
		return cur
	}
	for _, c := range []struct {
		path []string
		want any
	}{
		{[]string{"actor", "user", "uid"}, principalID.String()},
		{[]string{"actor", "user", "type_id"}, float64(1)},
		{[]string{"user", "uid"}, principalID.String()},
		{[]string{"src_endpoint", "ip"}, "203.0.113.7"},
		{[]string{"http_request", "user_agent"}, "Mozilla/5.0 (test)"},
		{[]string{"metadata", "uid"}, otherID.String()},
		{[]string{"metadata", "reporter", "name"}, "prod-eu"},
		{[]string{"metadata", "product", "name"}, "SystemForge"},
		{[]string{"metadata", "product", "vendor_name"}, "PlexusOne"},
		{[]string{"metadata", "product", "version"}, "v0.0.0-test"},
		{[]string{"auth_protocol_id"}, float64(events.AuthenticationAuthProtocolIDOAUTH20)},
		{[]string{"auth_protocol"}, "OAUTH 2.0"},
		{[]string{"status"}, "Success"},
		{[]string{"severity"}, "Informational"},
		{[]string{"class_name"}, "Authentication"},
		{[]string{"activity_name"}, "Logon"},
		{[]string{"type_name"}, "Authentication: Logon"},
		{[]string{"category_name"}, "Identity & Access Management"},
	} {
		if g := path(c.path...); g != c.want {
			t.Errorf("%s = %v, want %v", strings.Join(c.path, "."), g, c.want)
		}
	}
	for _, absent := range []string{"cloud", "osint", "unmapped"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s present: %s", absent, data)
		}
	}
}

func TestDetailsShapes(t *testing.T) {
	d := allowedDetails("systemauth.token.refused", map[string]any{
		"grant_type": "client_credentials",
		"client_id":  "alice@example.com",
		"reason":     "free text with spaces",
		"error":      "invalid_client",
		"other":      "x",
	})
	if len(d) != 2 || d["grant_type"] != "client_credentials" || d["error"] != "invalid_client" {
		t.Errorf("details: %v", d)
	}
	if got := allowedDetails("not.listed", map[string]any{"reason": "ok"}); len(got) != 0 {
		t.Errorf("details of an unlisted type: %v", got)
	}
	n := 7
	for _, c := range []struct {
		k    kind
		in   any
		want any
		ok   bool
	}{
		{kindInt, 3, int64(3), true},
		{kindInt, float64(4), int64(4), true},
		{kindInt, 4.5, nil, false},
		{kindInt, &n, int64(7), true},
		{kindInt, "3", nil, false},
		{kindUUID, principalID, principalID.String(), true},
		{kindUUID, uuid.Nil, nil, false},
		{kindUUID, "not-a-uuid", nil, false},
		{kindTime, "2026-01-02T03:04:05+01:00", "2026-01-02T02:04:05Z", true},
		{kindTime, "yesterday", nil, false},
		{kindBool, "true", nil, false},
	} {
		got, ok := normalize(c.k, c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("normalize(%d, %v) = %v, %v; want %v, %v", c.k, c.in, got, ok, c.want, c.ok)
		}
	}
	l, ok := normalize(kindUUIDList, []any{principalID.String(), "x", otherID})
	if !ok || len(l.([]string)) != 2 { //nolint:forcetypeassert // the test asserts the shape
		t.Errorf("uuid list: %v", l)
	}
}

// TestManagedEntityTypeIsOther checks that entities OCSF has no type for
// (keys, connections, SCIM tokens, sign-up codes and invites) carry
// type_id Other with their type named in type.
func TestManagedEntityTypeIsOther(t *testing.T) {
	m := newTestMapper()
	for _, tc := range []struct {
		ev   audit.Event
		want string
	}{
		{withResource(evt("keys", "key.created", audit.OutcomeSuccess, nil), audit.Resource{Type: "key", Identifier: "kek-1/v1"}), "key"},
		{evt("signup_invite.created", "created", audit.OutcomeSuccess, nil), "signup_invite"},
	} {
		data, err := json.Marshal(m.toOCSF(&tc.ev))
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Entity struct {
				TypeID int    `json:"type_id"`
				Type   string `json:"type"`
			} `json:"entity"`
		}
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if got.Entity.TypeID != objects.ManagedEntityTypeIDOther || got.Entity.Type != tc.want {
			t.Errorf("%s: entity type_id %d, type %q; want %d, %q", tc.ev.EventType, got.Entity.TypeID, got.Entity.Type, objects.ManagedEntityTypeIDOther, tc.want)
		}
	}
}

// TestUserAgentWithPersonalDataIsDropped checks that a client-sent
// User-Agent carrying an email address or a token is left out.
func TestUserAgentWithPersonalDataIsDropped(t *testing.T) {
	m := newTestMapper()
	for _, ua := range []string{"curl/8 alice@example.com", "app/1 eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig"} {
		ev := evt("systemauth.sign_in", "sign_in", audit.OutcomeSuccess, map[string]any{"method": "github"})
		ev.Context.UserAgent = ua
		data, err := json.Marshal(m.toOCSF(&ev))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "user_agent") || strings.Contains(string(data), "alice@") || strings.Contains(string(data), "eyJ") {
			t.Errorf("User-Agent %q reached the event: %s", ua, data)
		}
	}
}
