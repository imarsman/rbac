package roles_test

import (
	_ "embed"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/imarsman/rbac/roles"
	"github.com/matryer/is"
)

// casbin policy file loaded as string using embed
//go:embed policy.csv
var casbinPolicy string

// casbin model file loaded as string using embed
//go:embed model.conf
var casbinModel string

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
	loadModelOnce.Do(func() {
		roles.SetEnforcer(casbinPolicy, casbinModel)
	})
	fmt.Printf("Took %v to load model and policy", time.Since(start))
}

type objects struct {
	// General feed Obj
	Content string
	Account string
}

// Objects authorization Obj patterns
// These are role authorization inflection points, not specifically objects
var Objects = objects{
	Content: "obj-content",
	Account: "obj-account",
}

type actions struct {
	Read   string
	Write  string
	Create string
	Delete string
}

// Actions things that can be allowed on an object by a role
var Actions = actions{
	Read:   "read",
	Write:  "write",
	Create: "create",
	Delete: "delete",
}

// roles a struct defining various roles
type userRoles struct {
	User   string
	Editor string
	Admin  string
	Root   string
}

// Roles roles that can be granted to clients
var Roles = userRoles{
	User:   "user",
	Editor: "editor",
	Admin:  "admin",
	Root:   "root",
}

// user simulate a user with roles defined
type user struct {
	name  string
	roles []string
}

// newUser make a new user object
func newUser(name string, roles []string) user {
	u := new(user)
	u.name = name
	u.roles = roles
	return *u
}

// authObj simulate a struct that can be used to authorize an action
type authObj struct {
	user   user
	object string
	action string
}

// This can be used for things like http middleware when the user is known and
// the user's roles can be looked up. The user's roles can be authorized against
// the object and action. This is simulated by the canAct function.
func newAuthObj(u user, object, action string) authObj {
	ao := authObj{
		user:   u,
		object: object,
		action: action,
	}

	return ao
}

func (ao *authObj) canAct() bool {
	return roles.CheckAllowForRoles(ao.object, ao.action, ao.user.roles...)
}

func TestRole(t *testing.T) {
	is := is.New(t)

	userRole := []string{Roles.User}
	editorRole := []string{Roles.Editor}
	adminRole := []string{Roles.Admin}
	rootRole := []string{Roles.Root}

	baseUser := newUser("baseuser", userRole)
	editUser := newUser("edit", editorRole)
	adminUser := newUser("admin", adminRole)
	rootUser := newUser("admin", rootRole)

	start := time.Now()

	// base user can read content
	pass := roles.CheckAllowForRoles(Objects.Content, Actions.Read, baseUser.roles...)
	is.Equal(pass, true)

	// base user cannot create content
	pass = roles.CheckAllowForRoles(Objects.Content, Actions.Create, baseUser.roles...)
	is.Equal(pass, false)

	// editor can modify content
	pass = roles.CheckAllowForRoles(Objects.Content, Actions.Write, editUser.roles...)
	is.Equal(pass, true)

	// admin user can modify content
	pass = roles.CheckAllowForRoles(Objects.Content, Actions.Write, adminUser.roles...)
	is.Equal(pass, true)

	// admin user cannot delete content
	pass = roles.CheckAllowForRoles(Objects.Content, Actions.Delete, adminUser.roles...)
	is.Equal(pass, false)

	// root user can delete content
	pass = roles.CheckAllowForRoles(Objects.Content, Actions.Delete, rootUser.roles...)
	is.Equal(pass, true)

	// Get a go/no-go result for a struct function tied to an object and action
	u := newUser("base user", baseUser.roles)
	ao := newAuthObj(u, Objects.Content, Actions.Read)
	canAct := ao.canAct()
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

	rootRole := []string{Roles.Root}
	rootUser := newUser("admin", rootRole)

	var pass bool

	b.SetBytes(bechmarkBytesPerOp)
	b.ReportAllocs()
	b.SetParallelism(30)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pass = roles.CheckAllowForRoles(Objects.Content, Actions.Delete, rootUser.roles...)
		}
	})

	is.Equal(pass, true) // Should not have an empty time
}

func BenchmarkCheckRolesBare(b *testing.B) {
	is := is.New(b)

	// rootRole := []string{Roles.Root}
	// rootUser := newUser("admin", rootRole)

	var pass bool

	b.SetBytes(bechmarkBytesPerOp)
	b.ReportAllocs()
	b.SetParallelism(30)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pass = roles.CheckAllowForRoles(Objects.Content, Actions.Delete, []string{Roles.Root}...)
		}
	})

	is.Equal(pass, true) // Should not have an empty time
}
