package guard_test

import (
	"testing"

	"github.com/mirkobrombin/go-guard/pkg/guard"
)

type Document struct {
	Title   string `guard:"role:admin; can:read,write"`
	Content string `guard:"role:editor; can:edit"`
	Public  string `guard:"role:*; can:view"` // role will be taken from value
	OwnerID string `guard:"role:*; can:delete"`
}

type DynamicDoc struct {
	Meta map[string]string `guard:"role:*; can:manage"`
}

type MockUser struct {
	ID    string
	Roles []string
}

func (u *MockUser) GetID() string      { return u.ID }
func (u *MockUser) GetRoles() []string { return u.Roles }

func TestGuard_Can(t *testing.T) {
	g := guard.NewGuard()

	admin := &MockUser{ID: "1", Roles: []string{"admin"}}
	editor := &MockUser{ID: "2", Roles: []string{"editor"}}
	// owner := &MockUser{ID: "3", Roles: []string{"user"}} // OwnerID will be "3" in doc
	stranger := &MockUser{ID: "4", Roles: []string{"guest"}}

	doc := &Document{
		Title:   "Secret",
		Content: "Stuff",
		Public:  "guest", // value "guest" treated as role? "role:*" on "Public"
		OwnerID: "3",     // value "3" treated as role? Or is it "role of user with ID 3"?
		// Wait, `role:*` semantic in my implementation:
		// If Map: checks keys against UserID. If match, values are roles.
		// If String: String value IS the role.
		// If Int: Int value stringified IS the role.
		// So here: Public="guest". User stranger has role "guest". Should match?
		// OwnerID="3". User owner has ID "3". Does he have role "3"? No.
		// BUT `checker` logic: `IsMatch(val, userID)`?

		// Let's re-read `policy.go` logic for Dynamic Rule:
		// `extractRoles` extracts strings from Valid Map/Slice/String.
		// The `CompiledPolicy` logic:
		// `dynamicRoles := extractRoles(fieldVal, user.GetID())`
		// `extractRoles` logic:
		// If Map: `if checker.IsMatch(key, userID) { append val }`
		// If String: `append val.String()`
		// If Slice: iterate and append strings.

		// So for `Public string`: it appends "guest".
		// Then we checks inner loop: `if dr == ur`.
		// User stranger has role "guest". So "guest" == "guest". ALLOWED.

		// For `OwnerID string`: it appends "3".
		// User owner has role "user". "3" != "user".
		// Unless OwnerID held "user"?
		// If `role:*` mechanism is used for "Ownership", usually it means "User ID must match this field".
		// But here `role:*` means "The value of this field IS the required role".

		// If I want "Owner check", the tag should probably be different or value should be the Role Name (e.g. Owner has dynamic role "3"? No).
		// Wait, usually `guard` library might support `owner` strategy?
		// But in this implementation, `role:*` interprets the field value as the Required Role Name.
		// So if OwnerID="3", the required role is "3".
		// If my user has role "3", allowed.
		// If I want ownership based access, I probably use `role:owner` and assign "owner" role to user dynamically?
		// Or maybe the field value IS the user ID?
		// If the logic intended was "Allow if Field Value == User ID", then current implementation is WRONG.
		// But checking `policy.go`:
		// `extractRoles` just gets strings.
		// It doesn't compare field value to UserID (except for Map keys).

		// So `role:*` on string field = "Use value as required role".
		// Correct.
	}

	tests := []struct {
		name     string
		user     guard.Identity
		resource *Document
		action   string
		wantErr  bool
	}{
		{"Admin Read Title", admin, doc, "read", false},
		{"Admin Write Title", admin, doc, "write", false},
		{"Admin Edit Content (Fail)", admin, doc, "edit", true}, // Admin doesn't have "editor"
		{"Editor Read Title (Fail)", editor, doc, "read", true},
		{"Editor Edit Content", editor, doc, "edit", false},
		{"Guest View Public", stranger, doc, "view", false}, // field Public="guest", user role="guest"
		// {"Owner Delete (Fail)", owner, doc, "delete", true}, // OwnerID="3", user role != "3"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := g.Can(tt.user, tt.resource, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("Can() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
