"""barq permissions:install and the permissions:* commands."""

import os
import sys

from barq.project import run_in_project, write_new
from barq_framework.commands import MIGRATIONS, SEEDERS, migration_stamp


def cmd_permissions_install(args):
    """config/permissions.bq, the permission tables migration and an example seeder. Safe to run again."""
    from . import scaffold as sc
    files = [(os.path.join("config", "permissions.bq"), sc.PERMISSIONS_CONFIG),
             (os.path.join(SEEDERS, "RolesAndPermissionsSeeder.bq"), sc.PERMISSIONS_SEEDER)]
    for path, text in files:
        if os.path.exists(path):
            print(f"Kept {path} (already there)")
        elif write_new(path, text):
            return 1
    existing = os.listdir(MIGRATIONS) if os.path.isdir(MIGRATIONS) else []
    if any(f.endswith("_create_permission_tables.bq") for f in existing):
        print("Kept the create_permission_tables migration (already there)")
    elif write_new(os.path.join(MIGRATIONS, f"{migration_stamp()}_create_permission_tables.bq"), sc.PERMISSIONS_MIGRATION):
        return 1
    print("\nNext:\n  - run: barq migrate\n  - optional: barq db:seed --class RolesAndPermissionsSeeder"
          "\n  - in a model: user.assignRole(\"admin\"), user.can(\"edit posts\"); on routes: "
          "middleware(\"role:admin\") or middleware(\"permission:edit posts\")")
    return 0


def cmd_permissions(cmd, args):
    from .permissions import cli
    if cmd == "permissions:install":
        return cmd_permissions_install(args)
    engine = "tree" if "--interp" in args else None
    fn, err = cli(cmd, [a for a in args if a not in ("--interp", "--vm")])
    if err:
        sys.stderr.write(f"barq: {err}\n")
        return 2
    return run_in_project(fn, engine)
