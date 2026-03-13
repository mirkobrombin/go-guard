# Core Concepts

## Dynamic Roles vs Static Roles

*   **Static Roles**: Assigned to the user permanently (e.g., `admin`, `auditor`). These are returned by `GetRoles()`.
*   **Dynamic Roles**: Context-dependent (e.g., `owner`, `collaborator`). These are resolved at runtime by comparing the `Identity.GetID()` with annotated fields in the resource.

## Two-Pass Resolution
Go Guard performs a two-pass scan on your resource structure:

1.  **Resolution Pass**: Scans for `role:<name>` tags. If `Field Value == User ID`, the role is temporarily granted to the user for this specific request.
2.  **Authorization Pass**: Scans for `<action>:<roles>` tags. Checks if the user (with their static + resolved dynamic roles) satisfies the requirements.

This ensures that order of fields in the struct does not matter. You can define the Owner field at the bottom and the permission check at the top.
