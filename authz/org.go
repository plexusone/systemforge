package authz

// Organization permissions of the base SpiceDB schema: the membership
// ladder and organization administration. Check them with
// NewResourceWithID(ResourceTypeOrganization, orgID); both providers
// evaluate them the same way.
const (
	PermOrgManage       Action = "manage"
	PermOrgEdit         Action = "edit"
	PermOrgContribute   Action = "contribute"
	PermOrgView         Action = "view"
	PermOrgInviteMember Action = "invite_member"
	PermOrgRemoveMember Action = "remove_member"
	PermOrgChangeRole   Action = "change_role"
	PermOrgSettings     Action = "settings"
	PermOrgDelete       Action = "delete"
)

// OrgRolePermissions maps each organization role to its permissions,
// mirroring the organization definition in BaseSpiceDBSchema. A test keeps
// the two equal.
var OrgRolePermissions = map[string][]Action{
	"owner": {
		PermOrgManage, PermOrgEdit, PermOrgContribute, PermOrgView,
		PermOrgInviteMember, PermOrgRemoveMember, PermOrgChangeRole, PermOrgSettings,
		PermOrgDelete,
	},
	"admin": {
		PermOrgManage, PermOrgEdit, PermOrgContribute, PermOrgView,
		PermOrgInviteMember, PermOrgRemoveMember, PermOrgChangeRole, PermOrgSettings,
	},
	"editor": {PermOrgEdit, PermOrgContribute, PermOrgView},
	"member": {PermOrgContribute, PermOrgView},
	"viewer": {PermOrgView},
}

// OrgRoleAllows reports whether an organization role grants a permission
// of the base organization definition.
func OrgRoleAllows(role string, action Action) bool {
	for _, a := range OrgRolePermissions[role] {
		if a == action {
			return true
		}
	}
	return false
}

// IsOrgPermission reports whether action is a permission of the base
// organization definition.
func IsOrgPermission(action Action) bool {
	return OrgRoleAllows("owner", action)
}
