"""The files `barq permissions:install` writes: config/permissions.bq, the
permission tables migration and an example seeder."""

PERMISSIONS_CONFIG = '''// Roles and permissions (see docs/packages/barq-permissions.md)
dict<string, any> permissions = #{
    // Users with this role pass every check (user.can(), Gate, the "permission" middleware).
    // null: no super admin role.
    "super_admin_role": "super-admin",

    // "posts.*" covers "posts.create" and "posts.delete"; "*" covers everything
    "wildcards": true,

    // Roles, permissions and which role has which are kept in memory this long (seconds).
    // Changes made through Barq (or barq permissions:*) clear it right away.
    "cache": #{
        "expiration_time": 3600
    }
}
'''

PERMISSIONS_MIGRATION = '''namespace Database\\Migrations

// Tables for roles and permissions. A role or permission given to a model is
// stored with its class (model_type) and id (model_id); team_id is set when it
// was given for one team only.
class CreatePermissionTables extends Migration

    #[Public]
    #[void]
    karo up(Schema schema)
        schema.create("permissions", karo(Blueprint table): void
            table.id()
            table.string("name")
            table.string("guard_name")
            table.timestamps()
            table.unique(#["name", "guard_name"])
        )
        schema.create("roles", karo(Blueprint table): void
            table.id()
            table.string("name")
            table.string("guard_name")
            table.timestamps()
            table.unique(#["name", "guard_name"])
        )
        schema.create("role_has_permissions", karo(Blueprint table): void
            table.int("permission_id")
            table.int("role_id").index()
            table.unique(#["permission_id", "role_id"])
        )
        schema.create("model_has_roles", karo(Blueprint table): void
            table.int("role_id").index()
            table.morphs("model")
            table.int("team_id").nullable().index()
        )
        schema.create("model_has_permissions", karo(Blueprint table): void
            table.int("permission_id").index()
            table.morphs("model")
            table.int("team_id").nullable().index()
        )

    #[Public]
    #[void]
    karo down(Schema schema)
        schema.dropIfExists("model_has_permissions")
        schema.dropIfExists("model_has_roles")
        schema.dropIfExists("role_has_permissions")
        schema.dropIfExists("roles")
        schema.dropIfExists("permissions")
'''

PERMISSIONS_SEEDER = '''namespace Database\\Seeders

// Run with: barq db:seed --class RolesAndPermissionsSeeder
class RolesAndPermissionsSeeder extends Seeder

    #[Public]
    #[void]
    karo run()
        Permissions.forgetCache()

        list<string> perms = #[
            "view posts", "create posts", "edit posts", "delete posts", "publish posts",
            "view users", "edit users", "delete users",
            "view admin panel", "manage settings"
        ]
        for name in perms
            Permission.findOrCreate(name)

        Role.findOrCreate("admin").syncPermissions(perms)
        Role.findOrCreate("editor").syncPermissions(#["view posts", "create posts", "edit posts", "publish posts"])
        Role.findOrCreate("writer").syncPermissions(#["view posts", "create posts", "edit posts"])

        // no permissions needed: config permissions.super_admin_role passes every check
        Role.findOrCreate("super-admin")
'''
