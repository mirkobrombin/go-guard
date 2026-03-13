package guard_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mirkobrombin/go-guard/pkg/guard"
)

type Resource struct {
	Title string `guard:"role:admin; can:read,write"`
	Data  string `guard:"role:user; can:read"`
}

type User struct {
	ID    string
	Roles []string
}

func (u *User) GetID() string      { return u.ID }
func (u *User) GetRoles() []string { return u.Roles }

// Naive implementation simulating old behavior (parsing every time)
func CanNaive(user guard.Identity, resource any, action string) error {
	val := reflect.ValueOf(resource)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()

	userRoles := make(map[string]bool)
	for _, r := range user.GetRoles() {
		userRoles[r] = true
	}

	found := false
	allowed := false

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("guard")
		if tag == "" {
			continue
		}

		// Simulate parsing overhead (string splitting + allocation)
		parts := strings.Split(tag, ";")
		for _, part := range parts {
			kv := strings.Split(part, ":")
			if len(kv) != 2 {
				continue
			}
			key := strings.TrimSpace(kv[0])
			// Simulating "can" check
			// "can:read,write"
			if key == "can" {
				perms := strings.Split(kv[1], ",")
				for _, p := range perms {
					if strings.TrimSpace(p) == action {
						found = true
						// Simplified check for roles in same tag
						// In real naive impl, we would have parsed roles too.
						// Let's parse roles to be fair.
					}
				}
			}
		}

		// Re-scan for roles if found
		if found {
			for _, part := range parts {
				kv := strings.Split(part, ":")
				if strings.TrimSpace(kv[0]) == "role" {
					roles := strings.Split(kv[1], ",")
					for _, r := range roles {
						if userRoles[strings.TrimSpace(r)] {
							allowed = true
						}
					}
				}
			}
		}
	}

	if !found {
		return fmt.Errorf("no rule")
	}
	if !allowed {
		return fmt.Errorf("denied")
	}
	return nil
}

func BenchmarkCan_Cached(b *testing.B) {
	g := guard.NewGuard()
	u := &User{ID: "1", Roles: []string{"admin"}}
	res := &Resource{Title: "Test"}

	// Warmup cache
	_ = g.Can(u, res, "read")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = g.Can(u, res, "read")
	}
}

func BenchmarkCan_Naive(b *testing.B) {
	u := &User{ID: "1", Roles: []string{"admin"}}
	res := &Resource{Title: "Test"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CanNaive(u, res, "read")
	}
}
