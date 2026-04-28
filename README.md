# Go Guard

> [!CAUTION]
> go-guard is now part of the [go-foundation](https://github.com/mirkobrombin/go-foundation) framework. The v1.0.0 release mirrors go-guard v0.1.0, but future versions may introduce breaking changes. Please migrate your project.

**Go Guard** is a strictly declarative Attribute-Based Access Control (ABAC) library for Go.
It couples security policies directly with your data models using struct tags, ensuring that authorization logic travels with the data it protects.

## Features

*   **Declarative Policies**: Define `read`, `write`, `delete` permissions directly in struct tags.
*   **Dynamic Role Resolution**: Automatically map user attributes to roles (e.g., "if `User.ID == Resource.OwnerID`, grant `owner` role").
*   **Zero Boilerplate**: No external policy files or complex rule engines. Just `Can(user, resource, action)`.
*   **Type Safe**: Supports string, int, and generic comparisons.

## Installation

```bash
go get github.com/mirkobrombin/go-guard
```

## Quick Start
See [examples/basic/main.go](examples/basic/main.go) for a runnable demo.

```go
type Post struct {
    // Defines that whoever matches AuthorID gets the 'owner' role
    AuthorID string `guard:"role:owner"`

    // Permissions
    Content string `guard:"read:owner,guest; edit:owner; delete:admin"`
}

if err := guard.Can(user, post, "edit"); err != nil {
    // Forbidden
}
```

## Documentation

*   [Getting Started](docs/getting-started.md)
*   [Core Concepts](docs/concepts.md)
