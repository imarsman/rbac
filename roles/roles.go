package roles

import (
	"github.com/casbin/casbin"
)

func init() {
}

// checkEnforce check a role against rules
func checkEnforce(e *casbin.Enforcer, sub, obj, act string) bool {
	return e.Enforce(sub, obj, act)
}

// CheckAllowForRoles check object and action against list of groups
func CheckAllowForRoles(e *casbin.Enforcer, obj string, act string, roles ...string) bool {
	for _, r := range roles {
		var pass bool = checkEnforce(e, r, obj, act)
		if pass == true {
			return true
		}
	}
	return false
}
