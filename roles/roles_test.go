package roles_test

import (
	// Allow embedding of policy and model file data.
	_ "embed"

	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/casbin/casbin"
	"github.com/imarsman/rbac/roles"
	"github.com/matryer/is"

	// Adapter to allow enforcer to be created from a string
	scas "github.com/qiangmzsx/string-adapter"
)

// casbin policy file loaded as string using embed
//go:embed policy.csv
var casbinPolicy string

// casbin model file loaded as string using embed
//go:embed model.conf
var casbinModel string

var atomicValue atomic.Value

var loadModelOnce sync.Once

const bechmarkBytesPerOp int64 = 10

//                Tests and benchmarks
// -----------------------------------------------------
// benchmark
//   go test -run=XXX -bench=. -benchmem
// Get allocation information and pipe to less
//   go build -gcflags '-m -m' ./*.go 2>&1 |less
// Run all tests
//   go test -v
// Run one test and do allocation profiling
//   go test -run=XXX -bench=IterativeISOTimestampLong -gcflags '-m' 2>&1 |less
// Run a specific test by function name pattern
//  go test -run=TestParsISOTimestamp
//
//  go test -run=XXX -bench=.
//  go test -bench=. -benchmem -memprofile memprofile.out -cpuprofile cpuprofile.out
//  go tool pprof -http=:8080 memprofile.out
//  go tool pprof -http=:8080 cpuprofile.out

func init() {
	start := time.Now()
	SetEnforcer(casbinPolicy, casbinModel)
	fmt.Printf("Took %v to load model and policy", time.Since(start))
}

// enforcer get reference to the enforcer
func enforcer() *casbin.Enforcer {
	return atomicValue.Load().(*casbin.Enforcer)
}

func SetEnforcer(policy, model string) {
	sa := scas.NewAdapter(policy)
	e := casbin.NewEnforcer(casbin.NewModel(model), sa)

	atomicValue.Store(e)
}

// Object constants
const (
	ObjContent string = "obj-content"
	ObjAccount string = "obj-account"
)

// Action constants
const (
	ActionRead   string = "read"
	ActionWrite  string = "write"
	ActionCreate string = "create"
	ActionDelete string = "delete"
)

// Role constants
const (
	RoleUser   string = "user"
	RoleEditor string = "editor"
	RoleAdmin  string = "admin"
	RoleRoot   string = "root"
)

// User struct simulates a User with roles defined
type User struct {
	name  string
	roles []string
}

// NewUser make a new user object
func NewUser(name string, roles []string) User {
	u := new(User)
	u.name = name
	u.roles = roles
	return *u
}

// AuthObj simulates a struct that can be used to authorize an action
type AuthObj struct {
	user   User
	object string
	action string
}

// This can be used for things like http middleware when the user is known and
// the user's roles can be looked up. The user's roles can be authorized against
// the object and action. This is simulated by the canAct function.
func NewAuthObj(u User, object, action string) AuthObj {
	ao := AuthObj{
		user:   u,
		object: object,
		action: action,
	}

	return ao
}

// CanAct define whether one of a set of roles can act on an object
func (ao *AuthObj) CanAct() bool {
	return roles.HasValidRole(enforcer(), ao.object, ao.action, ao.user.roles...)
}

// TestRole test the basic role functionality
func TestRole(t *testing.T) {
	is := is.New(t)

	userRole := []string{RoleUser}
	editorRole := []string{RoleEditor}
	adminRole := []string{RoleAdmin}
	rootRole := []string{RoleRoot}

	baseUser := NewUser("baseuser", userRole)
	editUser := NewUser("edit", editorRole)
	adminUser := NewUser("admin", adminRole)
	rootUser := NewUser("admin", rootRole)

	start := time.Now()

	// base user can read content
	pass := roles.HasValidRole(enforcer(), ObjContent, ActionRead, baseUser.roles...)
	is.Equal(pass, true)

	// base user cannot create content
	pass = roles.HasValidRole(enforcer(), ObjContent, ActionCreate, baseUser.roles...)
	is.Equal(pass, false)

	// editor can modify content
	pass = roles.HasValidRole(enforcer(), ObjContent, ActionWrite, editUser.roles...)
	is.Equal(pass, true)

	// admin user can modify content
	pass = roles.HasValidRole(enforcer(), ObjContent, ActionWrite, adminUser.roles...)
	is.Equal(pass, true)

	// admin user cannot delete content
	pass = roles.HasValidRole(enforcer(), ObjContent, ActionDelete, adminUser.roles...)
	is.Equal(pass, false)

	// root user can delete content
	pass = roles.HasValidRole(enforcer(), ObjContent, ActionDelete, rootUser.roles...)
	is.Equal(pass, true)

	// Get a go/no-go result for a struct function tied to an object and action
	u := NewUser("base user", baseUser.roles)
	ao := NewAuthObj(u, ObjContent, ActionRead)
	canAct := ao.CanAct()
	is.Equal(canAct, true)

	t.Logf("Took %v to process after load", time.Since(start))
}

/*
Performance is typical for the benchmarks for the Casbin library.
https://casbin.org/docs/en/benchmark

go test -run=XXX -bench=. -benchmem

BenchmarkCheckRoles-12       11681 ns/op   0.86 MB/s   14861 B/op     181 allocs/op
BenchmarkCheckRolesBare-12   12578 ns/op   0.80 MB/s   14882 B/op     181 allocs/op
*/

func BenchmarkCheckRoles(b *testing.B) {
	is := is.New(b)

	rootRole := []string{RoleRoot}
	rootUser := NewUser("admin", rootRole)

	var pass bool

	b.SetBytes(bechmarkBytesPerOp)
	b.ReportAllocs()
	b.SetParallelism(30)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pass = roles.HasValidRole(enforcer(), ObjContent, ActionDelete, rootUser.roles...)
		}
	})

	is.Equal(pass, true) // Should not have an empty time
}
