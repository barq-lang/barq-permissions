"""barq-permissions test suite: roles, permissions, middleware and commands.

Run from this folder (needs a barq checkout next to this one, or BARQ_HOME):

    python3 tests/test_permissions.py
"""

import glob
import http.cookiejar
import json
import signal
import socket
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORE = os.environ.get("BARQ_HOME") or os.path.join(os.path.dirname(ROOT), "barq")
if not os.path.isdir(os.path.join(CORE, "barq")):
    sys.exit(f"cannot find the barq checkout at {CORE} — clone https://github.com/barq-lang/barq next to "
             "this repo or set BARQ_HOME")
sys.path.insert(0, CORE)

from barq import devtest  # noqa: E402
from barq.devtest import ENGINES, barq_env, fetch, free_port, run_barq, run_both, wait_for_port  # noqa: E402,F401

devtest.PACKAGES = "barq_permissions"
devtest.PATHS = [ROOT] + [os.path.join(os.path.dirname(ROOT), d) for d in ['barq-framework', 'barq-auth']]


class GoldenOutput(unittest.TestCase):
    """tests/cases/NAME.bq must print exactly tests/cases/NAME.out, on both engines."""


devtest.add_golden_tests(GoldenOutput, os.path.join(HERE, "cases"))


class PermissionCommands(unittest.TestCase):
    """barq permissions:* in a fresh project."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="barq-project-")
        with open(os.path.join(self.dir, ".env"), "w") as f:
            f.write("DB_PATH=storage/app.db\n")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def barq(self, *args, engine="vm"):
        extra = ["--interp"] if engine == "tree" and args[0].startswith(("migrate", "db:")) else []
        if engine == "tree" and args[0].endswith(".bq"):
            args = ("run", "--interp") + args
        proc = subprocess.run([sys.executable, "-m", "barq", *args, *extra], capture_output=True, text=True,
                              env=barq_env(), timeout=60, cwd=self.dir)
        return proc.returncode, proc.stdout, proc.stderr

    def write(self, rel, text):
        path = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)

    def edit(self, rel, old, new):
        path = os.path.join(self.dir, rel)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertIn(old, text)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text.replace(old, new))

    def test_permissions_commands(self):
        code, out, err = self.barq("permissions:install")
        self.assertEqual(code, 0, err)
        self.assertIn("Created config/permissions.bq", out)
        self.assertIn("Kept config/permissions.bq", self.barq("permissions:install")[1])     # safe to run again
        self.assertEqual(self.barq("make:model", "User", "-m")[0], 0)
        users = [m for m in os.listdir(os.path.join(self.dir, "database", "migrations")) if m.endswith("_create_users_table.bq")]
        self.edit(os.path.join("database", "migrations", users[0]), "table.id()", 'table.id()\n            table.string("email")')
        self.edit(os.path.join("app", "Models", "User.bq"), "fillable = #[]", 'fillable = #["email"]')
        self.assertEqual(self.barq("compile", "app", "database", "config")[0], 0)
        code, out, err = self.barq("migrate")
        self.assertEqual(code, 0, err)
        code, out, err = self.barq("db:seed", "--class", "RolesAndPermissionsSeeder")
        self.assertEqual(code, 0, err)
        self.write("mk.bq", 'use App\\Models\\User\nUser.create(#{"email": "a@x.test"})\n')
        self.assertEqual(self.barq("mk.bq")[0], 0)
        out = self.barq("permissions:list-roles")[1]
        self.assertRegex(out, r"admin\s+web\s+10\s+0")
        self.assertIn("publish posts     web    admin, editor", self.barq("permissions:list-permissions")[1])
        self.assertEqual(self.barq("permissions:create-role", "reviewer")[1], 'Created role "reviewer" (guard web)\n')
        self.assertIn("already exists", self.barq("permissions:create-role", "reviewer")[1])
        self.assertIn("(guard api)", self.barq("permissions:create-permission", "export reports", "--guard", "api")[1])
        self.assertEqual(self.barq("permissions:assign-role", "a@x.test", "editor")[0], 0)
        out = self.barq("permissions:show-user", "a@x.test")[1]
        self.assertIn("roles:       editor", out)
        self.assertIn("via roles:   create posts, edit posts, publish posts, view posts", out)
        self.assertIn("passes every check", self.barq("permissions:show-role", "super-admin")[1])
        self.assertEqual(self.barq("permissions:cache-reset")[1], "Permission cache cleared.\n")
        self.assertTrue(os.path.isfile(os.path.join(self.dir, ".barq", "permissions.stamp")))
        code, _, err = self.barq("permissions:assign-role", "nobody@x.test", "editor")
        self.assertEqual(code, 1)
        self.assertIn("no User with the email nobody@x.test", err)
        self.assertEqual(self.barq("permissions:show-role")[0], 2)
        self.write("check.bq", 'use App\\Models\\User\nUser u = User.first()\n'
                   'print(u.getRoleNames(), u.can("publish posts"), u.can("delete posts"), "reviewer" in Role.names())\n')
        for engine in ENGINES:
            with self.subTest(engine=engine):
                code, out, err = self.barq("check.bq", engine=engine)
                self.assertEqual((code, out), (0, '#["editor"] true false true\n'), err)


if __name__ == "__main__":
    unittest.main()
