package roles

import (
	// Allow loading of policy and model
	_ "embed"

	"github.com/casbin/casbin"
	// Adapter to use for casbin to create adapter from strings
	// - for embedded model and policy
)

// var atomicValue atomic.Value

// enforcer get reference to the enforcer
// func enforcer() *casbin.Enforcer {
// 	return atomicValue.Load().(*casbin.Enforcer)
// }

// SetEnforcer load in model and policy file for role enforcement and store it
// in atomic value. Failure to run this before using the enforcer will result in
// a panic.
// func SetEnforcer(policy, model string) {
// 	sa := scas.NewAdapter(policy)
// 	e := casbin.NewEnforcer(casbin.NewModel(model), sa)

// 	atomicValue.Store(e)
// }

func init() {
}

// checkEnforce check a role against rules
func checkEnforce(e *casbin.Enforcer, sub string, obj string, act string) bool {
	return e.Enforce(sub, obj, act)
}

// CheckAllowForRoles check object and action against list of groups
func CheckAllowForRoles(e *casbin.Enforcer, obj string, act string, roles ...string) bool {
	for _, r := range roles {
		pass := checkEnforce(e, r, obj, act)
		if pass == true {
			return true
		}
	}
	return false
}
