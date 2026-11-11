# Package — Barq Permissions

> The official roles & permissions package for the Barq framework.  
> Equivalent to **spatie/laravel-permission**.

> **Status (v0.16.0-alpha):** everything on this page is built (in the barq-permissions package) — nothing to set up beyond `barq permissions:install` (config, migration, example seeder) and `barq migrate`. Differences from spatie: the role methods are on every `Model` (`use HasRoles` is accepted but not needed); `hasRole(#[...])` means *all* of them; checking a permission that was never created is `false`; team assignments use a `team_id` column and an assignment without a team counts in every team; guests hitting `role:` / `permission:` get 401. See [README.md](../README.md#roles-and-permissions-v0160) and decisions #110–116 in [open-decisions.md](https://github.com/barq-lang/barq/blob/main/docs/open-decisions.md).

---

## Overview

Barq Permissions gives every user a set of roles and permissions, stored in the database. You can assign permissions directly to users, or assign them to roles and then give roles to users.

| Feature | Included |
|---------|---------|
| Roles (named groups of permissions) | ✅ |
| Permissions (fine-grained access flags) | ✅ |
| Assign roles to users | ✅ |
| Assign permissions directly to users | ✅ |
| Wildcard permissions | ✅ |
| Super admin role (bypass all checks) | ✅ |
| Multiple guards (web, api, admin) | ✅ |
| Permission caching | ✅ |
| Route middleware | ✅ |
| Artisan-style CLI commands | ✅ |
| Team-scoped permissions (with barq/auth Teams) | ✅ |

---

## Installation

```bash
# Generate the migration, config/permissions.bq and an example seeder
barq permissions:install

# Run migrations
barq migrate
```

---

## Database Tables Created

```
roles
  id, name, guard_name, created_at, updated_at

permissions
  id, name, guard_name, created_at, updated_at

role_has_permissions
  permission_id, role_id

model_has_roles
  role_id, model_type, model_id, team_id (nullable)

model_has_permissions
  permission_id, model_type, model_id, team_id (nullable)
```

---

## Setup — User Model

```barq
namespace App\Models

use Barq\Permissions\HasRoles

class User extends Model
    use HasRoles

    // ... rest of model
```

---

## Creating Roles & Permissions

```barq
use Barq\Permissions\Role
use Barq\Permissions\Permission

// Create permissions
Permission.create("view posts")
Permission.create("create posts")
Permission.create("edit posts")
Permission.create("delete posts")
Permission.create("publish posts")

Permission.create("view users")
Permission.create("create users")
Permission.create("edit users")
Permission.create("delete users")

Permission.create("view admin panel")
Permission.create("manage settings")

// Create roles
admin    = Role.create("admin")
editor   = Role.create("editor")
writer   = Role.create("writer")
moderator = Role.create("moderator")

// Assign permissions to roles
admin.givePermissionTo("view posts")
admin.givePermissionTo("create posts")
admin.givePermissionTo("edit posts")
admin.givePermissionTo("delete posts")
admin.givePermissionTo("publish posts")
admin.givePermissionTo("view users")
admin.givePermissionTo("view admin panel")
admin.givePermissionTo("manage settings")

// Assign multiple at once
editor.givePermissionTo(#[
    "view posts",
    "create posts",
    "edit posts",
    "publish posts"
])

writer.givePermissionTo(#[
    "view posts",
    "create posts",
    "edit posts"
])

moderator.givePermissionTo(#[
    "view posts",
    "delete posts"
])
```

---

## Assigning Roles to Users

```barq
// Assign a single role
user.assignRole("admin")

// Assign multiple roles
user.assignRole(#["admin", "editor"])

// Remove a role
user.removeRole("editor")

// Sync roles (replace all existing roles)
user.syncRoles(#["admin", "moderator"])

// Remove all roles
user.roles().detach()
```

---

## Checking Roles

```barq
user.hasRole("admin")                            → true/false
user.hasRole(#["admin", "super-admin"])          → false (must have all)
user.hasAnyRole(#["admin", "editor"])            → true (any one is enough)
user.hasAllRoles(#["admin", "editor"])           → true (must have both)

user.getRoleNames()                              → #["admin", "editor"]

// Role on specific guard
user.hasRole("admin", guard: "api")
```

---

## Assigning Permissions to Users

Permissions can be given directly to a user (bypassing roles):

```barq
// Give a permission directly
user.givePermissionTo("delete posts")

// Give multiple permissions
user.givePermissionTo(#["delete posts", "publish posts"])

// Revoke a direct permission
user.revokePermissionTo("delete posts")

// Sync direct permissions (replace all direct permissions)
user.syncPermissions(#["view posts", "edit posts"])
```

---

## Checking Permissions

```barq
// Check if user has permission (via role OR direct)
user.can("edit posts")                           → true/false
user.cannot("delete users")                      → true/false
user.hasPermissionTo("edit posts")               → true/false

// Check direct permission only (not via role)
user.hasDirectPermission("edit posts")           → true/false

// Check permission via role only
user.hasPermissionViaRole("edit posts")          → true/false

// Get all permissions (direct + via roles)
user.getAllPermissions()                         → list of Permission
user.getDirectPermissions()                      → list of Permission
user.getPermissionsViaRoles()                   → list of Permission
user.getPermissionNames()                        → #["edit posts", "view users", ...]
```

---

## Wildcard Permissions

Wildcard permissions let one permission rule cover many actions:

```barq
// Create wildcard permissions
Permission.create("posts.*")
Permission.create("users.*")
Permission.create("*")            // super permission — matches everything

// Assign wildcard to role
adminRole.givePermissionTo("posts.*")

// Check — wildcard automatically matches
user.can("posts.create")          → true  (covered by "posts.*")
user.can("posts.delete")          → true  (covered by "posts.*")
user.can("users.view")            → false (not covered by "posts.*")
```

---

## Super Admin

The super admin bypasses **all** permission checks. It is implemented via a gate hook rather than actual permission records.

```barq
// config/permissions.bq
return #{
    "super_admin_role": "super-admin"   // users with this role bypass all checks
}
```

```barq
// Create the super admin role
Role.create("super-admin")

// Assign to a user
user.assignRole("super-admin")

// user.can() now returns true for EVERYTHING
user.can("destroy the world")            → true (super admin bypasses all)
```

---

## Route Middleware

Protect routes by role or permission using middleware:

```barq
// Require a role
Route.get("/admin", #[AdminController, "index"]).middleware("role:admin")

// Require any of these roles
Route.get("/content", #[ContentController, "index"]).middleware("role:admin|editor|writer")

// Require a specific permission
Route.delete("/posts/:id", #[PostController, "destroy"]).middleware("permission:delete posts")

// Require any of these permissions
Route.put("/posts/:id", #[PostController, "update"]).middleware("permission:edit posts|publish posts")

// A role or a permission
Route.get("/moderate", #[ModerationController, "index"]).middleware("role_or_permission:moderator|delete posts")

// Require BOTH role AND permission
Route.get("/reports", #[ReportController, "index"]).middleware(#["role:admin", "permission:view admin panel"])

// Another guard's user: a second parameter
Route.get("/api/admin", #[AdminController, "stats"]).middleware(#["auth:api", "role:admin,api"])
```

A guest gets 401 (web pages redirect to the `login` route); a user without the role or permission gets 403.

---

## Checking Permissions in Controllers

```barq
class PostController

    #[Public]
    karo destroy(Request req, int id)
        // Method 1: abort unless allowed (403)
        Gate.authorize("delete posts")

        Post.findOrFail(id).delete()
        return redirect("/posts").with("success", "Post deleted")

    #[Public]
    karo publish(Request req, int id)
        // Method 2: check and answer yourself
        if not auth().user().can("publish posts")
            return Response.json(#{"error": "Forbidden"}, 403)

        Post post = Post.findOrFail(id)
        post.published_at = Date.now()
        post.save()
        return #{"success": true}
```

---

## Checking Permissions in Templates

```html
<!-- Show edit button only if user can edit -->
<if condition="{auth().user().can('edit posts')}">
    <a href="/posts/{post.id}/edit">Edit</a>
</if>

<!-- Show admin menu only for admins -->
<if condition="{auth().user().hasRole('admin')}">
    <div class="admin-menu">
        <a href="/admin/users">Users</a>
        <a href="/admin/settings">Settings</a>
    </div>
</if>

<!-- Show delete if admin OR moderator -->
<if condition="{auth().user().hasAnyRole(#['admin', 'moderator'])}">
    <button class="btn-danger">Delete</button>
</if>
```

---

## Team-Scoped Permissions (with barq/auth)

When used together with `barq/auth` Teams, permissions can be scoped to a team:

```barq
// Give permission within a specific team context
user.givePermissionTo("edit posts", team: currentTeam)
user.can("edit posts", team: currentTeam)              → true
user.can("edit posts", team: otherTeam)                → false

// Assign role within a team
user.assignRole("editor", team: currentTeam)
user.hasRole("editor", team: currentTeam)              → true
user.hasRole("editor", team: otherTeam)                → false
```

---

## CLI Commands

```bash
# List all roles
barq permissions:list-roles

# List all permissions
barq permissions:list-permissions

# List permissions for a role
barq permissions:show-role admin

# Create a role
barq permissions:create-role reviewer

# Create a permission
barq permissions:create-permission "export reports"

# Assign role to user (by email)
barq permissions:assign-role alice@example.com admin

# Clear permission cache
barq permissions:cache-reset

# Show all roles + permissions for a user
barq permissions:show-user alice@example.com
```

---

## Permission Caching

Permissions are cached automatically to avoid a database query on every `can()` check.

```barq
// config/permissions.bq
return #{
    "cache": #{
        "expiration_time": 3600,         // seconds (1 hour default)
        "key":             "barq.permission.cache",
        "store":           "default"     // which cache store to use
    }
}
```

**Cache is automatically reset when:**
- A permission is created, updated, or deleted
- A role is created, updated, or deleted
- A role or permission is assigned/removed from a user

```barq
// Manually reset if needed
barq permissions:cache-reset

// Or in code
Permissions.forgetCache()
app("barq.permissions.cache").forget()
```

---

## Seeder Example

```barq
namespace Database\Seeders

use Barq\Permissions\Role
use Barq\Permissions\Permission

class RolesAndPermissionsSeeder extends Seeder

    #[Public]
    #[void]
    karo run()
        // Reset cache
        app("barq.permissions.cache").forget()

        // Create permissions
        permissions = #[
            "view posts", "create posts", "edit posts",
            "delete posts", "publish posts",
            "view users", "edit users", "delete users",
            "view admin panel", "manage settings"
        ]

        for perm in permissions
            Permission.firstOrCreate(#{"name": perm})

        // Create roles and assign permissions
        adminRole = Role.firstOrCreate(#{"name": "admin"})
        adminRole.syncPermissions(permissions)   // admin gets everything

        editorRole = Role.firstOrCreate(#{"name": "editor"})
        editorRole.syncPermissions(#[
            "view posts","create posts","edit posts","publish posts"
        ])

        writerRole = Role.firstOrCreate(#{"name": "writer"})
        writerRole.syncPermissions(#[
            "view posts","create posts","edit posts"
        ])

        // Create super admin (no permissions needed — bypasses all checks)
        Role.firstOrCreate(#{"name": "super-admin"})
```

---

*Back to: [Barq Auth Package](https://github.com/barq-lang/barq-auth/blob/main/docs/barq-auth.md)*
*Back to: [Step 12 — Reserved Keywords](https://github.com/barq-lang/barq/blob/main/docs/step-12-reserved-keywords.md)*
