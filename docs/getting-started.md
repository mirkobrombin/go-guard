# Getting Started

## 1. Implement Identity Interface
Your User/Actor struct must implement the `guard.Identity` interface to allow the library to inspect its ID and static roles.

```go
type User struct {
    ID    string
    Roles []string
}

func (u User) GetID() string      { return u.ID }
func (u User) GetRoles() []string { return u.Roles }
```

## 2. Define Resources
Add `guard` tags to your struct fields.

*   `role:<name>`: Grants a dynamic role if the field value matches the user's ID.
*   `<action>:<role1>,<role2>`: Defines which roles are allowed to perform an action.

```go
type Document struct {
    OwnerID string `guard:"role:owner"`
    Data    string `guard:"read:owner,admin; write:owner"`
}
```

## 3. Check Permissions
Use `guard.Can()` to enforce rules.

```go
err := guard.Can(currentUser, document, "write")
```
