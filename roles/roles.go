package roles

import (
	"sync/atomic"

	// Allow loading of policy and model
	_ "embed"

	"github.com/casbin/casbin"

	// Adapter to use for casbin to create adapter from strings
	// - for embedded model and policy
	scas "github.com/qiangmzsx/string-adapter"
)

var atomicValue atomic.Value

// enforcer get reference to the enforcer
func enforcer() *casbin.Enforcer {
	return atomicValue.Load().(*casbin.Enforcer)
}

// SetEnforcer load in model and policy file for role enforcement and store it
// in atomic value. Failure to run this before using the enforcer will result in
// a panic.
func SetEnforcer(policy, model string) {
	sa := scas.NewAdapter(policy)
	e := casbin.NewEnforcer(casbin.NewModel(model), sa)

	atomicValue.Store(e)
}

func init() {
}

// checkEnforce check a role against rules
func checkEnforce(sub string, obj string, act string) bool {
	return enforcer().Enforce(sub, obj, act)
}

// CheckAllowForRoles check object and action against list of groups
func CheckAllowForRoles(obj string, act string, roles ...string) bool {
	for _, r := range roles {
		pass := checkEnforce(r, obj, act)
		if pass == true {
			return true
		}
	}
	return false
}
