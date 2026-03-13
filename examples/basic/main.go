package main

import (
	"fmt"

	"github.com/mirkobrombin/go-guard/pkg/guard"
)

type User struct {
	ID    string
	Roles []string
}

func (u User) GetID() string      { return u.ID }
func (u User) GetRoles() []string { return u.Roles }

// Post represents a resource protected by go-guard.
type Post struct {
	// The person matching AuthorID gets the 'owner' role.
	AuthorID string `guard:"role:owner"`

	// Access Policies
	Content string `guard:"read:owner,admin,guest; edit:owner,admin; delete:admin"`
}

func check(u User, p *Post, action string) {
	if err := guard.Can(u, p, action); err != nil {
		fmt.Printf("[DENY]  User %s cannot %s: %v\n", u.ID, action, err)
	} else {
		fmt.Printf("[ALLOW] User %s can %s\n", u.ID, action)
	}
}

func main() {
	post := &Post{AuthorID: "alice", Content: "Hello World"}

	alice := User{ID: "alice", Roles: []string{"user"}}
	bob := User{ID: "bob", Roles: []string{"guest"}}
	admin := User{ID: "admin", Roles: []string{"admin"}}

	fmt.Println("--- Alice (Owner) ---")
	check(alice, post, "read")
	check(alice, post, "edit")
	check(alice, post, "delete")

	fmt.Println("\n--- Bob (Guest) ---")
	check(bob, post, "read")
	check(bob, post, "edit")

	fmt.Println("\n--- Admin ---")
	check(admin, post, "delete")
	check(admin, post, "edit")
}
