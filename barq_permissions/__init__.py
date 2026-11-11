"""barq-permissions — roles and permissions for Barq (برق): Role and
Permission models, user.assignRole()/can(), wildcard permissions, team-scoped
roles, the role:/permission: middleware and the permissions:* commands.

Needs barq-auth (and so barq-framework).
"""

NAME = "barq-permissions"
__version__ = "0.21.0-alpha"
REQUIRES = ["barq_auth"]

USAGE = """
Permission commands (barq-permissions):
  barq permissions:install       Add the roles and permissions tables, config/permissions.bq
                                 and an example seeder
  barq permissions:list-roles    Print every role (also list-permissions, show-role <role>,
                                 create-role <name>, create-permission "<name>" (--guard name),
                                 assign-role <email> <role>, show-user <email>, cache-reset)
"""


def cmd_permissions(cmd, args):
    from .commands import cmd_permissions as run
    return run(cmd, args)


def register(hooks):
    from . import permissions
    hooks.INSTALLERS.append(permissions.install)
    hooks.add_prefix_command("permissions:", cmd_permissions)
    hooks.USAGE.append(USAGE)
