# barq-permissions

Roles and permissions for Barq: `Role` and `Permission` models, `user.assignRole()` / `can()` / `hasRole()`, wildcard permissions (`posts.*`), a super-admin role, team-scoped roles, the `role:`, `permission:` and `role_or_permission:` middleware, and the `permissions:*` commands.

Part of [Barq (برق)](https://github.com/barq-lang/barq). Needs [barq-auth](https://github.com/barq-lang/barq-auth) (and so barq-framework).

## Install

```bash
git clone https://github.com/barq-lang/barq
git clone https://github.com/barq-lang/barq-framework
git clone https://github.com/barq-lang/barq-auth
git clone https://github.com/barq-lang/barq-permissions
barq/bin/barq packages        # lists barq-permissions
```

The `barq` command loads packages cloned next to the `barq` checkout (or listed in `BARQ_PATH`); see [Repositories and packages](https://github.com/barq-lang/barq#repositories-and-packages).

## Tests

```bash
cd barq-permissions && python3 tests/test_permissions.py    # both engines; finds ../barq (or set BARQ_HOME)
```

## Roles and permissions (v0.16.0)

Like spatie/laravel-permission in Laravel. Code: `barq_permissions/permissions.py`; design notes: [docs/barq-permissions.md](docs/barq-permissions.md). Tests: [tests/cases/permissions.bq](tests/cases/permissions.bq) and `ProjectCommands.test_permissions_commands`.

```bash
barq permissions:install      # config/permissions.bq, the tables migration, RolesAndPermissionsSeeder
barq migrate
barq db:seed --class RolesAndPermissionsSeeder
```

```barq
use Barq\Permissions\Role               // optional: Role, Permission and HasRoles are global
use Barq\Permissions\Permission

Permission.create("edit posts")         // or Permission.create(#{"name": ...}), findOrCreate(name, guard?)
Role editor = Role.create("editor")     // guard "web" unless you pass one: Role.create("admin", "api")
editor.givePermissionTo("edit posts", "publish posts")      // names, lists, ids or Permission objects
editor.revokePermissionTo("publish posts")    editor.syncPermissions(#["edit posts"])
editor.hasPermissionTo("edit posts")   editor.getPermissionNames()   editor.permissions()   editor.users()
Role.findByName("editor")   Role.findById(1)   Role.names()   Permission.findByName("edit posts").assignRole("editor")

user.assignRole("editor")               // also assignRole("a", "b") or assignRole(#["a", "b"])
user.removeRole("editor")   user.syncRoles(#["admin"])   user.roles().detach()
user.hasRole("admin")                   // a list means all of them: hasRole(#["admin", "editor"])
user.hasAnyRole(#["admin", "editor"])   user.hasAllRoles(#["admin", "editor"])   user.getRoleNames()
user.hasRole("admin", guard: "api")

user.givePermissionTo("delete posts")   user.revokePermissionTo("delete posts")   user.syncPermissions(#[...])
user.hasPermissionTo("edit posts")      // directly or through a role
user.hasDirectPermission("x")   user.hasPermissionViaRole("x")   user.hasAnyPermission(#[...])   user.hasAllPermissions(#[...])
user.getAllPermissions()   user.getDirectPermissions()   user.getPermissionsViaRoles()   user.getPermissionNames()
user.can("edit posts")                  // the Gate asks the permissions first

user.assignRole("editor", team: acme)   // only in that team
user.hasRole("editor", team: acme)   user.can("edit posts", team: acme)   user.getRoleNames(acme)

Route.get("/admin", handler).middleware("role:admin")              // admin
Route.get("/content", handler).middleware("role:admin|editor")     // either one
Route.put("/posts/:id", handler).middleware("permission:edit posts|publish posts")
Route.get("/x", handler).middleware("role_or_permission:admin|edit posts")
Route.get("/api/admin", handler).middleware(#["auth:api", "role:admin,api"])   // ",api": that guard's user
```

- **Every model has these methods**, like the team methods. `use HasRoles` in a model is accepted (it's an empty built-in trait), so code written from the package docs works, but it isn't needed.
- **Assignments** live in `model_has_roles` / `model_has_permissions` with the model's class name (`model_type`, e.g. `App\Models\User`) and id. So a `Staff` model can have roles too: `editor.users(Staff)`. Deleting a model deletes its assignments; deleting a role or permission deletes its links.
- **Guards:** a role or permission belongs to one guard (`guard_name`, the auth default guard when not given). A name passed to `assignRole()` / `givePermissionTo()` means the one of the model's default guard. A `Role` object or id may be of any guard whose user provider is that model's class; otherwise it's a `PermissionException`. Checks without `guard:` count roles of every guard.
- **The Gate:** before anything else, `user.can(ability)` / `Gate.allows(ability)` / the `can:` and `permission:` middleware are true when the user has a permission with that name. Otherwise abilities and policies decide as before. A user with config `permissions.super_admin_role` (`"super-admin"` in the generated config, `null` by default) passes every check. `role:` middleware checks roles only, so the super admin doesn't skip it.
- **Wildcards** (config `permissions.wildcards`, on by default): a granted `posts.*` covers `posts.create` and `posts.drafts.create`, but not `posts`; `*` covers everything. Checking a name that was never created is just `false`; giving or assigning one is a `PermissionException`.
- **Teams:** pass `team:` (a team model or its id). An assignment without a team counts in every team; one with a team counts only there. `roles(team)` / `permissions(team)` are exactly that team's assignments, `roles()` the ones without a team. Deleting a team (`TeamModel`) deletes its assignments. Needs the `team_id` column, which `permissions:install` creates.
- **Middleware:** a guest gets 401 (web: a redirect to the `login` route), a user without the role or permission 403 with `"User does not have the right roles."` / `"...permissions."`. A second parameter picks the guard: `"role:admin,api"`.
- **Cache:** roles, permissions and their links are read once and kept for config `permissions.cache.expiration_time` seconds (3600; 0 means no cache). Any change made through Barq clears it. With a database file, it also touches `.barq/permissions.stamp`, so a running `barq serve` sees changes from `barq permissions:*` commands at once. `Permissions.forgetCache()` or `app("barq.permissions.cache").forget()` clear it by hand. A model's own roles are read from the database on each check (one small query per table).
- **Events:** `permissions.role_assigned` and `permissions.role_removed` get `#{"user", "roles", "team"}`.
- **CLI:** `barq permissions:list-roles`, `list-permissions`, `show-role <role>`, `create-role <name>`, `create-permission "<name>"` (both take `--guard api`), `assign-role <email> <role>`, `show-user <email>`, `cache-reset`.
- **Named arguments:** a variadic built-in can now take keyword-only named arguments after its `*rest` parameter, which is how `user.can("x", team: t)` and `assignRole("a", "b", team: t)` work.
- **Tables:** `permissions` and `roles` (id, name, guard_name, timestamps), `role_has_permissions` (permission_id, role_id), `model_has_roles` (role_id, model_type, model_id, team_id), `model_has_permissions` (permission_id, model_type, model_id, team_id).

## License

MIT — see [LICENSE](LICENSE).
