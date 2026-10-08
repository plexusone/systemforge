package authz

import (
	"testing"
)

func TestManagerRoleAllows(t *testing.T) {
	if !ManagerRoleAllows(ManagerRoleGuardian, PermManageAccount) {
		t.Error("guardian should manage the account")
	}
	if ManagerRoleAllows(ManagerRoleEducator, PermManageAccount) || ManagerRoleAllows(ManagerRoleEducator, PermManageManagers) {
		t.Error("educator should not manage the account or managers")
	}
	if ManagerRoleAllows("coach", PermViewProfile) {
		t.Error("unregistered role should grant nothing")
	}
}
