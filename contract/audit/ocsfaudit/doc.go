// Package ocsfaudit writes SystemForge's security events as OCSF
// (Open Cybersecurity Schema Framework) events, one JSON object per line,
// for a security data lake or SIEM that ingests OCSF.
//
// An Emitter is an audit.Emitter. A host passes it wherever an emitter is
// taken, such as systemauthsvc.Options.AuditEmitter, alone or with
// audit.NewMultiEmitter next to audit.NewLogEmitter:
//
//	f, err := os.OpenFile("/var/log/systemauth/security.ocsf.jsonl",
//		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
//	if err != nil {
//		return err
//	}
//	ocsf := ocsfaudit.New(f, ocsfaudit.Options{Deployment: "prod-eu"})
//	defer ocsf.Close() // before f.Close
//	opts.AuditEmitter = audit.NewMultiEmitter(audit.NewLogEmitter(logger), ocsf)
//
// # Delivery
//
// Emit maps the event and queues the line without blocking or logging;
// one goroutine writes the queue in order, one Write per line. When the
// queue (Options.BufferSize) is full, the event is dropped and counted:
// Dropped returns the count, and a reporter goroutine logs it once a
// minute and on Close, so the logger is never called on the request path.
// Write failures, short writes included, are logged at most once a minute
// and counted by WriteFailures; after a Write that fails part-way the next
// line starts with a newline, so only the torn line is lost. Close writes
// what is queued, flushes a writer with Flush (*bufio.Writer) and syncs
// one with Sync (*os.File); it does not close the writer.
//
// The package does not rotate files. Rotate by renaming, with a writer
// that reopens its file on a signal, and have the rotation wait for the
// reopen (with delaycompress when compressing); copytruncate can lose the events
// written between its copy and its truncation.
//
// # Event classes
//
// Every event type SystemForge emits maps to an OCSF 1.10.0-dev class and
// activity; metadata.event_code keeps the SystemForge event type.
//
//	Event type                                Class (uid)                 Activity                                  Severity
//	systemauth.sign_in                        Authentication (3002)       Logon                                     Informational; Low on failure
//	systemauth.sign_out                       Authentication (3002)       Logoff                                    Informational
//	systemauth.token.refused                  Authentication (3002)       Logon, OAuth 2.0                          Low
//	systemauth.refresh_token.reuse            Authentication (3002)       Logon, OAuth 2.0                          High
//	systemauth.authorization_code.reuse       Authentication (3002)       Logon, OAuth 2.0                          High
//	systemauth.token.revoked                  Authentication (3002)       Logoff, OAuth 2.0                         Informational; Low on failure
//	systemauth.token_family.revoked           Authentication (3002)       Logoff, OAuth 2.0                         Informational
//	systemauth.email_verification.sent,       Authentication (3002)       Preauth (purpose verify_email)            Informational
//	systemauth.email.verified                 User Management (3007)      Update (purpose email_change)
//	systemauth.email_change.requested,        User Management (3007)      Update                                    Informational
//	systemauth.email_change.cancelled,
//	systemauth.email.changed
//	systemauth.signing_key.loaded             Application Lifecycle (6002) Start                                    Informational
//	systemauth.production.waiver              Application Lifecycle (6002) Start                                    Medium
//	organization.membership                   Group Management (3006)     Add User, Remove User, Update             Informational; Medium for ownership_transferred
//	principal.platform_admin                  User Management (3007)      Assign / Remove Privileges                High when granted
//	service_account                           User Management (3007)      Create, Enable, Disable, Delete,          Informational
//	                                                                      Add / Remove Programmatic Credentials,
//	                                                                      Assign / Remove Roles
//	keys                                      Entity Management (3004)    by action                                 High when compromised; Medium for destroy,
//	                                                                                                                shred, wrap or job failure, guard denial
//	connections                               Entity Management (3004)    by event                                  Medium for access.denied
//	scim_token.issued / rotated / revoked     Entity Management (3004)    Create / Update / Deactivate              Informational
//	scim_token.authentication_failed          Authentication (3002)       Logon, Failure                            Medium
//	signup_code.*, signup_invite.*,           Entity Management (3004)    Create, Update, Deactivate                Informational
//	signup_waitlist.invited,
//	signup_allowance.set
//	managed_principal.created, deleted,       User Management (3007)      Create, Delete, Update,                   Informational; Low for deleted
//	released, email_*, claim_*, manager_added,                            Add / Remove Programmatic Credentials
//	manager_removed, login_token_*
//	managed_principal.manager_invite*         Entity Management (3004)    Create, Update, Deactivate                Informational
//	managed_principal.session_revoked,        Authentication (3002)       Logoff                                    Informational
//	all_revoked
//	any other event type                      Base Event (0)              Other, named by the action                Informational; Low on failure
//
// A failure outcome raises Informational to Low. Severity High and above
// sets is_alert.
//
// # Common attributes
//
//	time                       the event time, in milliseconds
//	metadata.uid               the event ID, or a new UUID
//	metadata.correlation_uid   the request ID
//	metadata.event_code        the SystemForge event type
//	metadata.tenant_uid        the organization (Context.TenantID, or the organization_id detail)
//	metadata.product           Options.ProductName, VendorName, ProductVersion
//	metadata.version           the OCSF schema version (events.SchemaVersion)
//	metadata.reporter.name     Options.Deployment
//	actor.user.uid             the acting principal's ID; actor.application names an OAuth client by client ID
//	src_endpoint.ip            the client address
//	http_request.user_agent    the client's User-Agent, sanitized (audit.SanitizeUserAgent)
//	status_id, status_detail   the outcome and SystemForge's reason code; status_code the OAuth error code
//
// # What is never written
//
// Only IDs and addresses identify people. No event carries a name, an
// email address, a token or token prefix, a code, a DPoP proof, an
// assertion, a secret or a request body, in any attribute including
// unmapped and message. Actor and resource identifiers, which may be
// email addresses, are left out (an OAuth client ID, a SystemForge
// component name and a key ID excepted), and so is Context.SessionID,
// which may hold a session token; a revoked managed-principal session is
// named by its record UUID in session.uid. A User-Agent holding an email
// address or a credential-like value is left out.
// Details are copied only from an allowlist per event type, and only
// values of the expected shape: a code (no spaces, no @), a UUID, a
// boolean, a number or a time. A detail of an event type without an
// allowlist is never copied.
package ocsfaudit
