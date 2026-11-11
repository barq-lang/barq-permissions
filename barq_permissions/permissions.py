"""Roles and permissions (v0.16.0): the barq/permissions package, built in.

    Role / Permission    built-in models on the roles and permissions tables:
                         Role.create("editor"), Permission.findByName("edit posts"),
                         role.givePermissionTo("edit posts", "publish posts")
    user methods         user.assignRole("editor"), user.hasRole("admin"), user.givePermissionTo("x"),
                         user.hasPermissionTo("posts.create"), user.getRoleNames() — on every model
    HasRoles             an empty trait, so `use HasRoles` in a model reads like the docs
    Gate                 user.can("edit posts") is true when the user has that permission
                         (directly or through a role, wildcards included); the super admin role
                         (config permissions.super_admin_role) passes every check
    middleware           "role:admin|editor", "permission:edit posts|publish posts",
                         "role_or_permission:admin|edit posts" (",api" after them picks a guard)
    teams                assignRole("editor", team: t), hasRole("editor", team: t), can("x", team: t):
                         an assignment without a team counts in every team

Assignments are stored per model (model_type = the class's full name, model_id).
Roles, permissions and which role has which permission are cached in memory for
config permissions.cache.expiration_time seconds and reloaded after every change
made through Barq. With a database file, a change in another process (a CLI
command) reaches running apps through the stamp file .barq/permissions.stamp.
"""

import os
import time

from barq.builtins import need
from barq.runtime import BarqClass, BarqObject, BarqThrow, NativeFunction, PropInfo, split_kwargs, to_display, type_name
from barq.stdlib import module

ROLES = "roles"
PERMS = "permissions"
ROLE_PERMS = "role_has_permissions"
MODEL_ROLES = "model_has_roles"
MODEL_PERMS = "model_has_permissions"
TABLES = (ROLES, PERMS, ROLE_PERMS, MODEL_ROLES, MODEL_PERMS)
DEFAULTS = {
    "super_admin_role": None,       # users with this role pass every Gate check
    "wildcards": True,              # "posts.*" covers "posts.create"
    "cache": {"expiration_time": 3600, "key": "barq.permissions.cache"},
}
INSTALL_HINT = 'run "barq permissions:install" and "barq migrate"'


def throw(i, message, n, cls="PermissionException"):
    i.throw(cls, message, n)


def settings(i):
    from barq_auth.auth import merged
    from barq.stdlib2 import config_lookup
    c = config_lookup(i, "permissions")
    return merged(DEFAULTS, c) if isinstance(c, dict) else DEFAULTS


def role_cls(i):
    return i.classes["Role"]


def perm_cls(i):
    return i.classes["Permission"]


def is_role(i, v):
    return isinstance(v, BarqObject) and v.cls.is_subclass_of(role_cls(i))


def is_perm(i, v):
    return isinstance(v, BarqObject) and v.cls.is_subclass_of(perm_cls(i))


def pdb(i, n):
    from barq_framework.orm import meta, model_db
    return model_db(i, meta(i, role_cls(i), n), n)


def sql(i, query, params, n):
    from barq.stdlib2 import db_rows, db_run, db_state
    return db_rows(db_run(i, db_state(i, pdb(i, n), n), query, params, n))


def existing_tables(i, n):
    rows = sql(i, "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN (?, ?, ?, ?, ?)", list(TABLES), n)
    return {r["name"] for r in rows}


def key(i, model, n):
    from barq_framework.orm import meta, mstate
    return mstate(model).attrs.get(meta(i, model.cls, n).pk)


def default_guard(i):
    from barq_auth.auth import settings as auth_settings
    return auth_settings(i)["default_guard"]


def guards_for(i, cls, n):
    """The guards whose user provider is this model's class, the default guard first.
    Roles and permissions of these guards can be given to the model."""
    from barq_auth.auth import settings as auth_settings, user_model
    s = auth_settings(i)
    first = s["default_guard"]
    out = []
    for g in [first] + [x for x in s["guards"] if x != first]:
        provider = (s["guards"].get(g) or {}).get("provider")
        try:
            model = user_model(i, provider, n)
        except BarqThrow:
            continue
        if isinstance(model, BarqClass) and cls.is_subclass_of(model):
            out.append(g)
    return out or [first]


def resolve_for(i, cls_name, v, model, n, fname):
    """A role/permission to give to a model: a name means the one of the model's default
    guard; a model or id may be of any of the model's guards."""
    guards = guards_for(i, model.cls, n)
    if isinstance(v, str):
        return resolve(i, cls_name, v, guards[0], n, fname)
    row = resolve(i, cls_name, v, None, n, fname)
    if row["guard_name"] not in guards:
        throw(i, f'{fname}(): the {kind_of(cls_name)} "{row["name"]}" belongs to guard "{row["guard_name"]}", which '
              f'{model.cls.name} does not use (its guards: {", ".join(guards)})', n)
    return row


# ===========================================================================
# cache of roles, permissions and role -> permissions
# ===========================================================================

class Defs:
    def __init__(self):
        self.roles = {}         # id -> {"id", "name", "guard_name"}
        self.perms = {}
        self.role_perms = {}    # role id -> set of permission ids
        self.team_cols = {}     # pivot table -> has a team_id column
        self.loaded = 0.0
        self.stamp = None


def stamp_path(i, n):
    """Only a database file is shared between processes; :memory: needs no stamp."""
    path = getattr(pdb(i, n).native, "path", None)
    if not path or path == ":memory:" or not i.root:
        return None
    return os.path.join(i.root, ".barq", "permissions.stamp")


def stamp_of(path):
    if path is None:
        return None
    try:
        return os.stat(path).st_mtime_ns
    except OSError:
        return None


def forget(i, n=None):
    """Drop the cached definitions here, and tell other processes through the stamp file."""
    i._perm_defs = None
    try:
        path = stamp_path(i, n)
    except BarqThrow:
        path = None
    if path is not None:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(str(time.time_ns()))
        except OSError:
            pass
    return True


def defs(i, n, fname=None):
    """The cached definitions; None when the tables are missing (only when fname is None:
    with a function name, missing tables are an error)."""
    d = i.__dict__.get("_perm_defs")
    ttl = settings(i)["cache"].get("expiration_time")
    if d is not None:
        fresh = ttl is None or time.monotonic() - d.loaded < ttl
        if fresh and stamp_of(stamp_path(i, n)) == d.stamp:
            return d
    have = existing_tables(i, n)
    if len(have) < len(TABLES):
        if fname is None:
            return None
        missing = ", ".join(t for t in TABLES if t not in have)
        throw(i, f"{fname}(): roles and permissions need the tables {missing} — {INSTALL_HINT}", n)
    d = Defs()
    d.stamp = stamp_of(stamp_path(i, n))
    for r in sql(i, f'SELECT "id", "name", "guard_name" FROM "{ROLES}"', [], n):
        d.roles[r["id"]] = r
    for r in sql(i, f'SELECT "id", "name", "guard_name" FROM "{PERMS}"', [], n):
        d.perms[r["id"]] = r
    for r in sql(i, f'SELECT "role_id", "permission_id" FROM "{ROLE_PERMS}"', [], n):
        d.role_perms.setdefault(r["role_id"], set()).add(r["permission_id"])
    for t in (MODEL_ROLES, MODEL_PERMS):
        d.team_cols[t] = any(r["name"] == "team_id" for r in sql(i, f'PRAGMA table_info("{t}")', [], n))
    d.loaded = time.monotonic()
    if ttl != 0:
        i._perm_defs = d
    return d


# ===========================================================================
# finding roles and permissions
# ===========================================================================

def kind_of(cls_name):
    return "role" if cls_name == "Role" else "permission"


def table_of(cls_name):
    return ROLES if cls_name == "Role" else PERMS


def find_def(d, cls_name, name, guard):
    rows = d.roles if cls_name == "Role" else d.perms
    for r in rows.values():
        if r["name"] == name and (guard is None or r["guard_name"] == guard):
            return r
    return None


def hydrate_ids(i, cls_name, ids, n):
    """Models for ids, in name order."""
    from barq_framework.orm import hydrate
    if not ids:
        return []
    marks = ", ".join("?" for _ in ids)
    rows = sql(i, f'SELECT * FROM "{table_of(cls_name)}" WHERE "id" IN ({marks}) ORDER BY "name", "id"', list(ids), n)
    return [hydrate(i, i.classes[cls_name], r) for r in rows]


def resolve(i, cls_name, v, guard, n, fname):
    """A role/permission given as a name, an id or a model -> its definition row."""
    d = defs(i, n, fname)
    what = kind_of(cls_name)
    rows = d.roles if cls_name == "Role" else d.perms
    if isinstance(v, BarqObject) and v.cls.is_subclass_of(i.classes[cls_name]):
        row = rows.get(key(i, v, n))
        if row is None:
            throw(i, f"{fname}(): save the {what} first", n)
    elif isinstance(v, int) and not isinstance(v, bool):
        row = rows.get(v)
        if row is None:
            throw(i, f"{fname}(): there is no {what} with id {v}", n)
    elif isinstance(v, str):
        row = find_def(d, cls_name, v, guard)
        if row is None:
            elsewhere = find_def(d, cls_name, v, None)
            hint = (f' (there is one for guard "{elsewhere["guard_name"]}")' if elsewhere is not None else
                    f" — create it first: {cls_name}.create(\"{v}\")")
            throw(i, f'{fname}(): there is no {what} named "{v}" for guard "{guard}"{hint}', n)
    else:
        i.throw("TypeException", f"{fname}() takes {what} names, ids or {cls_name} objects, got {type_name(v)}", n)
    if guard is not None and row["guard_name"] != guard:
        throw(i, f'{fname}(): the {what} "{row["name"]}" belongs to guard "{row["guard_name"]}", not "{guard}"', n)
    return row


def flat(args):
    out = []
    for a in args:
        if isinstance(a, list):
            out.extend(flat(a))
        elif a is not None:
            out.append(a)
    return out


def names_arg(i, v, n, fname):
    """A name or a list of names (models and ids allowed) -> list."""
    items = flat([v]) if isinstance(v, list) else [v]
    if not items:
        i.throw("ValueException", f"{fname}() needs at least one name", n)
    return items


def wild_match(pattern, name):
    """posts.* covers posts.create (and posts.drafts.create); * covers everything."""
    if pattern == "*":
        return True
    p, q = pattern.split("."), name.split(".")
    for k, part in enumerate(p):
        if part == "*" and k == len(p) - 1:
            return len(q) > k
        if k >= len(q) or (part != "*" and part != q[k]):
            return False
    return len(p) == len(q)


def grants(i, granted, name):
    if name in granted:
        return True
    if settings(i).get("wildcards"):
        return any("*" in g and wild_match(g, name) for g in granted)
    return False


def label_of(v, i):
    if isinstance(v, BarqObject):
        from barq_framework.orm import mstate
        return str(mstate(v).attrs.get("name"))
    return to_display(v, i)


# ===========================================================================
# teams
# ===========================================================================

def team_id(i, team, n, fname):
    from barq_framework.orm import is_model
    if team is None:
        return None
    if isinstance(team, (int, str)) and not isinstance(team, bool):
        return team
    if is_model(i, team):
        k = key(i, team, n)
        if k is None:
            throw(i, f"{fname}(): save the team first", n)
        return k
    i.throw("TypeException", f"{fname}() team: needs a team model or its id, got {type_name(team)}", n)


def team_sql(i, d, table, tid, exact, n, fname):
    """-> (sql, params). Without a team: assignments without one. With a team: exactly
    that team's (exact), or that team's plus the ones without a team (checks)."""
    if not d.team_cols.get(table):
        if tid is not None:
            throw(i, f'{fname}(): the {table} table has no team_id column — add t.int("team_id").nullable() '
                  "(barq permissions:install does)", n)
        return "", []
    if tid is None:
        return ' AND "team_id" IS NULL', []
    if exact:
        return ' AND "team_id" = ?', [tid]
    return ' AND ("team_id" IS NULL OR "team_id" = ?)', [tid]


# ===========================================================================
# what a model has
# ===========================================================================

def need_saved(i, model, n, fname):
    from barq_framework.orm import is_model
    if not is_model(i, model) or is_role(i, model) or is_perm(i, model):
        i.throw("TypeException", f"{fname}() needs a model such as a User, got {type_name(model)}", n)
    k = key(i, model, n)
    if k is None:
        throw(i, f"{fname}(): save the {model.cls.name} first", n)
    return k


def assigned(i, model, tid, n, fname, exact=False):
    """-> (role ids, direct permission ids) of a saved model."""
    d = defs(i, n, fname)
    mid = need_saved(i, model, n, fname)
    out = []
    for table, col in ((MODEL_ROLES, "role_id"), (MODEL_PERMS, "permission_id")):
        cond, params = team_sql(i, d, table, tid, exact, n, fname)
        rows = sql(i, f'SELECT "{col}" FROM "{table}" WHERE "model_type" = ? AND "model_id" = ?{cond}',
                   [model.cls.fqn, mid] + params, n)
        out.append({r[col] for r in rows})
    return d, out[0], out[1]


def role_ids_of(d, rids, guard):
    return {r for r in rids if r in d.roles and (guard is None or d.roles[r]["guard_name"] == guard)}


def via_roles(d, rids):
    out = set()
    for r in rids:
        out |= d.role_perms.get(r, set())
    return out


def perm_names(d, pids, guard=None):
    return {d.perms[p]["name"] for p in pids if p in d.perms and (guard is None or d.perms[p]["guard_name"] == guard)}


class Ctx:
    """The parsed arguments of a user method."""
    def __init__(self, i, this, a, n, fname, guard_at=None, team_at=None):
        self.fname = f"{this.cls.name}.{fname}"
        pos, kw = split_kwargs(a)
        self.args = pos
        self.guard = kw.get("guard")
        team = kw.get("team")
        if guard_at is not None and len(pos) > guard_at and pos[guard_at] is not None:
            self.guard = pos[guard_at]
        if team_at is not None and len(pos) > team_at and pos[team_at] is not None:
            team = pos[team_at]
        if self.guard is not None:
            need(i, self.guard, ("string",), self.fname, (guard_at or 0) + 1, n)
        self.tid = team_id(i, team, n, self.fname)


# ---- roles ------------------------------------------------------------------

def write_assign(i, model, table, col, ids, tid, n, fname, remove=False, only=None):
    d = defs(i, n, fname)
    mid = need_saved(i, model, n, fname)
    cond, params = team_sql(i, d, table, tid, True, n, fname)
    base = [model.cls.fqn, mid] + params
    current = {r[col] for r in sql(i, f'SELECT "{col}" FROM "{table}" WHERE "model_type" = ? AND "model_id" = ?{cond}',
                                     base, n)}
    if remove:
        gone = [x for x in ids if x in current] if only is None else [x for x in current if x not in only]
        for x in gone:
            sql(i, f'DELETE FROM "{table}" WHERE "model_type" = ? AND "model_id" = ?{cond} AND "{col}" = ?', base + [x], n)
        return gone
    cols = f'"{col}", "model_type", "model_id"' + (', "team_id"' if d.team_cols.get(table) else "")
    added = []
    for x in dict.fromkeys(ids):
        if x in current:
            continue
        vals = [x, model.cls.fqn, mid] + ([tid] if d.team_cols.get(table) else [])
        sql(i, f'INSERT INTO "{table}" ({cols}) VALUES ({", ".join("?" for _ in vals)})', vals, n)
        added.append(x)
    return added


def u_assign_role(i, a, n, this):
    c = Ctx(i, this, a, n, "assignRole")
    ids = [resolve_for(i, "Role", r, this, n, c.fname)["id"] for r in names_arg(i, c.args, n, c.fname)]
    if write_assign(i, this, MODEL_ROLES, "role_id", ids, c.tid, n, c.fname):
        fire(i, "permissions.role_assigned", this, ids, c.tid, n)
    return this


def u_remove_role(i, a, n, this):
    c = Ctx(i, this, a, n, "removeRole")
    ids = [resolve(i, "Role", r, None, n, c.fname)["id"] for r in names_arg(i, c.args, n, c.fname)
           if not isinstance(r, str) or find_def(defs(i, n, c.fname), "Role", r, None) is not None]
    if write_assign(i, this, MODEL_ROLES, "role_id", ids, c.tid, n, c.fname, remove=True):
        fire(i, "permissions.role_removed", this, ids, c.tid, n)
    return this


def u_sync_roles(i, a, n, this):
    c = Ctx(i, this, a, n, "syncRoles")
    ids = [resolve_for(i, "Role", r, this, n, c.fname)["id"] for r in flat(c.args)]
    write_assign(i, this, MODEL_ROLES, "role_id", [], c.tid, n, c.fname, remove=True, only=set(ids))
    write_assign(i, this, MODEL_ROLES, "role_id", ids, c.tid, n, c.fname)
    return this


def user_role_rows(i, this, c, n):
    d, rids, _ = assigned(i, this, c.tid, n, c.fname)
    return [d.roles[r] for r in role_ids_of(d, rids, c.guard)]


def role_check(mode):
    def fn(i, a, n, this):
        name = {"one": "hasRole", "any": "hasAnyRole", "all": "hasAllRoles"}[mode]
        c = Ctx(i, this, a, n, name, guard_at=1, team_at=2)
        have = user_role_rows(i, this, c, n)
        names = {r["name"] for r in have}
        ids = {r["id"] for r in have}

        def has(v):
            if isinstance(v, str):
                return v in names
            if isinstance(v, int) and not isinstance(v, bool):
                return v in ids
            if is_role(i, v):
                return key(i, v, n) in ids
            i.throw("TypeException", f"{c.fname}() takes role names, ids or Role objects, got {type_name(v)}", n)
        wanted = names_arg(i, c.args[0], n, c.fname)
        if mode == "any":
            return any(has(v) for v in wanted)
        return all(has(v) for v in wanted)
    return fn


def u_role_names(i, a, n, this):
    c = Ctx(i, this, a, n, "getRoleNames", team_at=0)
    return sorted(r["name"] for r in user_role_rows(i, this, c, n))


def morph_relation(i, this, related, pivot, col, tid, n, fname):
    from barq_framework.orm import mq, relation_of
    d = defs(i, n, fname)
    need_saved(i, this, n, fname)
    rel = relation_of(i, this, "BelongsToMany", [related, pivot, "model_id", col], n)
    extra = {"model_type": this.cls.fqn}
    if d.team_cols.get(pivot):
        extra["team_id"] = tid
    elif tid is not None:
        team_sql(i, d, pivot, tid, True, n, fname)       # throws: no team_id column
    mq(rel).rel.extra = extra
    return rel


def u_roles(i, a, n, this):
    c = Ctx(i, this, a, n, "roles", team_at=0)
    return morph_relation(i, this, role_cls(i), MODEL_ROLES, "role_id", c.tid, n, c.fname)


def u_permissions(i, a, n, this):
    c = Ctx(i, this, a, n, "permissions", team_at=0)
    return morph_relation(i, this, perm_cls(i), MODEL_PERMS, "permission_id", c.tid, n, c.fname)


# ---- permissions --------------------------------------------------------------

def u_give(i, a, n, this):
    c = Ctx(i, this, a, n, "givePermissionTo")
    ids = [resolve_for(i, "Permission", p, this, n, c.fname)["id"] for p in names_arg(i, c.args, n, c.fname)]
    write_assign(i, this, MODEL_PERMS, "permission_id", ids, c.tid, n, c.fname)
    return this


def u_revoke(i, a, n, this):
    c = Ctx(i, this, a, n, "revokePermissionTo")
    d = defs(i, n, c.fname)
    ids = [resolve(i, "Permission", p, None, n, c.fname)["id"] for p in names_arg(i, c.args, n, c.fname)
           if not isinstance(p, str) or find_def(d, "Permission", p, None) is not None]
    write_assign(i, this, MODEL_PERMS, "permission_id", ids, c.tid, n, c.fname, remove=True)
    return this


def u_sync_perms(i, a, n, this):
    c = Ctx(i, this, a, n, "syncPermissions")
    ids = [resolve_for(i, "Permission", p, this, n, c.fname)["id"] for p in flat(c.args)]
    write_assign(i, this, MODEL_PERMS, "permission_id", [], c.tid, n, c.fname, remove=True, only=set(ids))
    write_assign(i, this, MODEL_PERMS, "permission_id", ids, c.tid, n, c.fname)
    return this


def perm_sets(i, this, c, n):
    """-> (direct names, names through roles) for the user, filtered by guard."""
    d, rids, pids = assigned(i, this, c.tid, n, c.fname)
    rids = role_ids_of(d, rids, c.guard)
    return d, perm_names(d, pids, c.guard), perm_names(d, via_roles(d, rids), c.guard)


def perm_name(i, v, n, fname):
    if isinstance(v, str):
        return v
    if is_perm(i, v) or (isinstance(v, int) and not isinstance(v, bool)):
        return resolve(i, "Permission", v, None, n, fname)["name"]
    i.throw("TypeException", f"{fname}() takes permission names, ids or Permission objects, got {type_name(v)}", n)


def perm_check(mode):
    name = {"to": "hasPermissionTo", "direct": "hasDirectPermission", "role": "hasPermissionViaRole",
            "any": "hasAnyPermission", "all": "hasAllPermissions"}[mode]

    def fn(i, a, n, this):
        c = Ctx(i, this, a, n, name, guard_at=1 if mode == "to" else None, team_at=2 if mode == "to" else 1)
        _, direct, roles = perm_sets(i, this, c, n)
        granted = direct if mode == "direct" else roles if mode == "role" else direct | roles
        wanted = [perm_name(i, v, n, c.fname) for v in names_arg(i, c.args[0], n, c.fname)]
        if mode == "any":
            return any(grants(i, granted, w) for w in wanted)
        return all(grants(i, granted, w) for w in wanted)
    return fn


def perm_list(mode):
    name = {"all": "getAllPermissions", "direct": "getDirectPermissions", "role": "getPermissionsViaRoles",
            "names": "getPermissionNames"}[mode]

    def fn(i, a, n, this):
        c = Ctx(i, this, a, n, name, team_at=0)
        d, rids, pids = assigned(i, this, c.tid, n, c.fname)
        ids = pids if mode == "direct" else via_roles(d, rids) if mode == "role" else pids | via_roles(d, rids)
        if mode == "names":
            return sorted(perm_names(d, ids))
        return hydrate_ids(i, "Permission", sorted(ids), n)
    return fn


# ===========================================================================
# Gate
# ===========================================================================

def gate_check(i, user, ability, args, n):
    """Asked before every Gate check: true for the super admin role and for a granted
    permission (direct, through a role, or a wildcard); otherwise the Gate goes on."""
    from barq_framework.orm import is_model, mstate
    if not isinstance(ability, str) or not is_model(i, user) or is_role(i, user) or is_perm(i, user):
        return None
    if not mstate(user).exists:
        return None
    try:
        d = defs(i, n)
    except BarqThrow:
        return None                             # no database configured: not our business
    if d is None:
        return None
    tid = team_id(i, i.__dict__.get("_perm_team"), n, f"{user.cls.name}.can")
    _, rids, pids = assigned(i, user, tid, n, f"{user.cls.name}.can")
    sa = settings(i).get("super_admin_role")
    if sa and any(d.roles[r]["name"] == sa for r in rids if r in d.roles):
        return True
    if grants(i, perm_names(d, pids | via_roles(d, rids)), ability):
        return True
    return None


# ===========================================================================
# Role and Permission models
# ===========================================================================

def s_create(cls_name):
    def fn(i, a, n, cls):
        from barq_framework.orm import new_model, save
        fname = f"{cls_name}.create"
        defs(i, n, fname)
        if isinstance(a[0], dict):
            data = dict(a[0])
        else:
            data = {"name": need(i, a[0], ("string", "dict"), fname, 1, n)}
        if len(a) > 1 and a[1] is not None:
            data["guard_name"] = need(i, a[1], ("string",), fname, 2, n)
        model = new_model(i, cls, data, n)
        save(i, model, n)
        return model
    return fn


def s_find_by_name(cls_name, by_id=False):
    def fn(i, a, n, cls):
        fname = f"{cls_name}.{'findById' if by_id else 'findByName'}"
        guard = need(i, a[1], ("string",), fname, 2, n) if len(a) > 1 and a[1] is not None else default_guard(i)
        if by_id:
            need(i, a[0], ("int",), fname, 1, n)
        else:
            need(i, a[0], ("string",), fname, 1, n)
        row = resolve(i, cls_name, a[0], guard, n, fname)
        return hydrate_ids(i, cls_name, [row["id"]], n)[0]
    return fn


def s_find_or_create(cls_name):
    def fn(i, a, n, cls):
        fname = f"{cls_name}.findOrCreate"
        name = need(i, a[0], ("string",), fname, 1, n)
        guard = need(i, a[1], ("string",), fname, 2, n) if len(a) > 1 and a[1] is not None else default_guard(i)
        row = find_def(defs(i, n, fname), cls_name, name, guard)
        if row is not None:
            return hydrate_ids(i, cls_name, [row["id"]], n)[0]
        return s_create(cls_name)(i, [name, guard], n, cls)
    return fn


def s_names(cls_name):
    def fn(i, a, n, cls):
        fname = f"{cls_name}.names"
        guard = a[0] if a and a[0] is not None else None
        d = defs(i, n, fname)
        rows = d.roles if cls_name == "Role" else d.perms
        return sorted({r["name"] for r in rows.values() if guard is None or r["guard_name"] == guard})
    return fn


def statics(cls_name):
    return {
        "create": (s_create(cls_name), 1, 2, ("name", "guard")),
        "findByName": (s_find_by_name(cls_name), 1, 2, ("name", "guard")),
        "findById": (s_find_by_name(cls_name, by_id=True), 1, 2, ("id", "guard")),
        "findOrCreate": (s_find_or_create(cls_name), 1, 2, ("name", "guard")),
        "names": (s_names(cls_name), 0, 1, ("guard",)),
    }


def own_row(i, this, n, fname):
    from barq_framework.orm import mstate
    k = key(i, this, n)
    if k is None or not mstate(this).exists:
        throw(i, f"{fname}(): save the {kind_of(this.cls.name)} first", n)
    d = defs(i, n, fname)
    row = (d.roles if is_role(i, this) else d.perms).get(k)
    if row is None:
        throw(i, f"{fname}(): this {kind_of(this.cls.name)} is not in the database any more", n)
    return d, row


def link_rows(i, role_ids, perm_ids, n, remove=False):
    changed = 0
    for r in role_ids:
        for p in perm_ids:
            if remove:
                sql(i, f'DELETE FROM "{ROLE_PERMS}" WHERE "role_id" = ? AND "permission_id" = ?', [r, p], n)
                changed += 1
            elif not sql(i, f'SELECT 1 FROM "{ROLE_PERMS}" WHERE "role_id" = ? AND "permission_id" = ?', [r, p], n):
                sql(i, f'INSERT INTO "{ROLE_PERMS}" ("role_id", "permission_id") VALUES (?, ?)', [r, p], n)
                changed += 1
    if changed:
        forget(i, n)
    return changed


def r_give(i, a, n, this):
    fname = "Role.givePermissionTo"
    _, row = own_row(i, this, n, fname)
    ids = [resolve(i, "Permission", p, row["guard_name"], n, fname)["id"] for p in names_arg(i, list(a), n, fname)]
    link_rows(i, [row["id"]], ids, n)
    return this


def r_revoke(i, a, n, this):
    fname = "Role.revokePermissionTo"
    d, row = own_row(i, this, n, fname)
    ids = [resolve(i, "Permission", p, None, n, fname)["id"] for p in names_arg(i, list(a), n, fname)
           if not isinstance(p, str) or find_def(d, "Permission", p, None) is not None]
    link_rows(i, [row["id"]], ids, n, remove=True)
    return this


def r_sync(i, a, n, this):
    fname = "Role.syncPermissions"
    d, row = own_row(i, this, n, fname)
    ids = [resolve(i, "Permission", p, row["guard_name"], n, fname)["id"] for p in flat(list(a))]
    current = d.role_perms.get(row["id"], set())
    link_rows(i, [row["id"]], [p for p in current if p not in ids], n, remove=True)
    link_rows(i, [row["id"]], ids, n)
    return this


def r_has_permission(i, a, n, this):
    fname = "Role.hasPermissionTo"
    d, row = own_row(i, this, n, fname)
    granted = perm_names(d, d.role_perms.get(row["id"], set()))
    return grants(i, granted, perm_name(i, a[0], n, fname))


def r_permission_names(i, a, n, this):
    d, row = own_row(i, this, n, "Role.getPermissionNames")
    return sorted(perm_names(d, d.role_perms.get(row["id"], set())))


def r_permissions(i, a, n, this):
    from barq_framework.orm import relation_of
    own_row(i, this, n, "Role.permissions")
    return relation_of(i, this, "BelongsToMany", [perm_cls(i), ROLE_PERMS, "role_id", "permission_id"], n)


def r_users(i, a, n, this):
    """Users with this role: models of the role's guard (or the class given)."""
    from barq_auth.auth import guard_config, user_model
    from barq_framework.orm import mq, need_model_class, relation_of
    fname = "Role.users"
    _, row = own_row(i, this, n, fname)
    if a and a[0] is not None:
        cls = need_model_class(i, a[0], n, fname)
    else:
        cls = user_model(i, guard_config(i, row["guard_name"], n)[1], n)
    rel = relation_of(i, this, "BelongsToMany", [cls, MODEL_ROLES, "role_id", "model_id"], n)
    mq(rel).rel.extra = {"model_type": cls.fqn}
    return rel


def p_assign_role(remove=False):
    def fn(i, a, n, this):
        fname = f"Permission.{'removeRole' if remove else 'assignRole'}"
        d, row = own_row(i, this, n, fname)
        roles = names_arg(i, list(a), n, fname)
        if remove:
            roles = [r for r in roles if not isinstance(r, str) or find_def(d, "Role", r, None) is not None]
        ids = [resolve(i, "Role", r, None if remove else row["guard_name"], n, fname)["id"] for r in roles]
        link_rows(i, ids, [row["id"]], n, remove=remove)
        return this
    return fn


def p_sync_roles(i, a, n, this):
    fname = "Permission.syncRoles"
    d, row = own_row(i, this, n, fname)
    ids = [resolve(i, "Role", r, row["guard_name"], n, fname)["id"] for r in flat(list(a))]
    current = [r for r, ps in d.role_perms.items() if row["id"] in ps]
    link_rows(i, [r for r in current if r not in ids], [row["id"]], n, remove=True)
    link_rows(i, ids, [row["id"]], n)
    return this


def p_roles(i, a, n, this):
    from barq_framework.orm import relation_of
    own_row(i, this, n, "Permission.roles")
    return relation_of(i, this, "BelongsToMany", [role_cls(i), ROLE_PERMS, "permission_id", "role_id"], n)


def p_role_names(i, a, n, this):
    d, row = own_row(i, this, n, "Permission.getRoleNames")
    return sorted(d.roles[r]["name"] for r, ps in d.role_perms.items() if row["id"] in ps and r in d.roles)


ROLE_METHODS = {
    "givePermissionTo": (r_give, 1, -1, None),
    "revokePermissionTo": (r_revoke, 1, -1, None),
    "syncPermissions": (r_sync, 0, -1, None),
    "hasPermissionTo": (r_has_permission, 1, 1, ("permission",)),
    "getPermissionNames": (r_permission_names, 0, 0, None),
    "permissions": (r_permissions, 0, 0, None),
    "users": (r_users, 0, 1, ("model",)),
}
PERMISSION_METHODS = {
    "assignRole": (p_assign_role(), 1, -1, None),
    "removeRole": (p_assign_role(remove=True), 1, -1, None),
    "syncRoles": (p_sync_roles, 0, -1, None),
    "roles": (p_roles, 0, 0, None),
    "getRoleNames": (p_role_names, 0, 0, None),
}


# ---- what happens when models are written --------------------------------------

def on_write(i, obj, what, n):
    if is_role(i, obj) or is_perm(i, obj):
        from barq_framework.orm import mstate
        cls_name = "Role" if is_role(i, obj) else "Permission"
        attrs = mstate(obj).attrs
        if what == "creating":
            name = attrs.get("name")
            if not isinstance(name, str) or not name.strip():
                throw(i, f"{cls_name}.create(): a {kind_of(cls_name)} needs a name", n)
            if attrs.get("guard_name") is None:
                attrs["guard_name"] = default_guard(i)
            if sql(i, f'SELECT 1 FROM "{table_of(cls_name)}" WHERE "name" = ? AND "guard_name" = ?',
                   [name, attrs["guard_name"]], n):
                throw(i, f'a {kind_of(cls_name)} named "{name}" already exists for guard "{attrs["guard_name"]}"', n)
            return
        if what == "deleted":
            k = attrs.get("id")
            col = "role_id" if cls_name == "Role" else "permission_id"
            sql(i, f'DELETE FROM "{ROLE_PERMS}" WHERE "{col}" = ?', [k], n)
            sql(i, f'DELETE FROM "{MODEL_ROLES if cls_name == "Role" else MODEL_PERMS}" WHERE "{col}" = ?', [k], n)
        forget(i, n)
        return
    if what != "deleted":
        return
    # a deleted user loses its assignments; a deleted team its team-scoped ones
    try:
        d = defs(i, n)
    except BarqThrow:
        return
    if d is None:
        return
    from barq_framework.orm import mstate, meta
    k = mstate(obj).attrs.get(meta(i, obj.cls, n).pk)
    if k is None:
        return
    team_base = i.classes.get("TeamModel")
    for table in (MODEL_ROLES, MODEL_PERMS):
        sql(i, f'DELETE FROM "{table}" WHERE "model_type" = ? AND "model_id" = ?', [obj.cls.fqn, k], n)
        if team_base is not None and obj.cls.is_subclass_of(team_base) and d.team_cols.get(table):
            sql(i, f'DELETE FROM "{table}" WHERE "team_id" = ?', [k], n)


def fire(i, name, user, role_ids, tid, n):
    from barq_auth.auth import fire as auth_fire
    d = defs(i, n)
    names = sorted(d.roles[r]["name"] for r in role_ids if d is not None and r in d.roles)
    auth_fire(i, name, {"user": user, "roles": names, "team": tid}, n)


# ===========================================================================
# middleware: role, permission, role_or_permission
# ===========================================================================

def mw_user(i, req, guard, n):
    from barq_auth.auth import guard_obj, resolve_user
    from barq.web import current
    with current(i, req):
        g = guard.strip() if guard and guard.strip() else req.native.guard if getattr(req.native, "guard", None) \
            else default_guard(i)
        user = resolve_user(i, guard_obj(i, g, n).native, n)
    if user is None:
        obj = i.make_exception("AuthenticationException", "Unauthenticated.", n)
        obj.fields["status"] = 401
        raise BarqThrow(obj)
    return user, g


def mw_items(i, extra, name, n):
    items = [x.strip() for x in (extra[0] if extra else "").split("|") if x.strip()]
    if not items:
        i.throw("ValueException", f'the "{name}" middleware needs a list: "{name}:admin|editor"', n)
    return items, (extra[1] if len(extra) > 1 else None)


def mw_check(kind):
    def fn(i, a, n):
        from barq_auth.auth import deny, inspect
        from barq.web import current
        req, nxt, extra = a[0], a[1], a[2:]
        items, guard = mw_items(i, extra, kind, n)
        user, g = mw_user(i, req, guard, n)
        ok = False
        if kind in ("role", "role_or_permission"):
            ok = role_check("any")(i, [items, g if guard else None], n, user)
        if not ok and kind in ("permission", "role_or_permission"):
            with current(i, req):
                ok = any(inspect(i, user, p, [], n)[0] for p in items)
        if not ok:
            deny(i, {"role": "User does not have the right roles.",
                     "permission": "User does not have the right permissions.",
                     "role_or_permission": "User does not have any of the necessary access rights."}[kind], n)
        return i.call_function(nxt, [req], n)
    return fn


# ===========================================================================
# Permissions module, the cache object, the HasRoles trait
# ===========================================================================

def m_tables(i, a, n):
    have = existing_tables(i, n)
    return {t: t in have for t in TABLES}


PERMISSIONS = {
    "forgetCache": (lambda i, a, n: forget(i, n), 0, 0),
    "tables": (m_tables, 0, 0),
    "superAdminRole": (lambda i, a, n: settings(i).get("super_admin_role"), 0, 0),
    "matches": (lambda i, a, n: wild_match(need(i, a[0], ("string",), "Permissions.matches", 1, n),
                                           need(i, a[1], ("string",), "Permissions.matches", 2, n)), 2, 2),
}


class EmptyDecl:
    members = []


def native(name, fn, lo, hi, names=None, owner=None):
    f = NativeFunction(name, fn, lo, hi)
    f.arg_names = names
    f.owner = owner
    return f


USER_METHODS = {
    "roles": (u_roles, 0, 1, ("team",)),
    "permissions": (u_permissions, 0, 1, ("team",)),
    "assignRole": (u_assign_role, 1, -1, ("*roles", "team")),
    "removeRole": (u_remove_role, 1, -1, ("*roles", "team")),
    "syncRoles": (u_sync_roles, 0, -1, ("*roles", "team")),
    "hasRole": (role_check("one"), 1, 3, ("roles", "guard", "team")),
    "hasAnyRole": (role_check("any"), 1, 3, ("roles", "guard", "team")),
    "hasAllRoles": (role_check("all"), 1, 3, ("roles", "guard", "team")),
    "getRoleNames": (u_role_names, 0, 1, ("team",)),
    "givePermissionTo": (u_give, 1, -1, ("*permissions", "team")),
    "revokePermissionTo": (u_revoke, 1, -1, ("*permissions", "team")),
    "syncPermissions": (u_sync_perms, 0, -1, ("*permissions", "team")),
    "hasPermissionTo": (perm_check("to"), 1, 3, ("permission", "guard", "team")),
    "hasDirectPermission": (perm_check("direct"), 1, 2, ("permission", "team")),
    "hasPermissionViaRole": (perm_check("role"), 1, 2, ("permission", "team")),
    "hasAnyPermission": (perm_check("any"), 1, 2, ("permissions", "team")),
    "hasAllPermissions": (perm_check("all"), 1, 2, ("permissions", "team")),
    "getAllPermissions": (perm_list("all"), 0, 1, ("team",)),
    "getDirectPermissions": (perm_list("direct"), 0, 1, ("team",)),
    "getPermissionsViaRoles": (perm_list("role"), 0, 1, ("team",)),
    "getPermissionNames": (perm_list("names"), 0, 1, ("team",)),
}


def install(i):
    from barq_auth.auth import PRE_CHECKS
    from barq_framework.framework import cstate
    from barq_framework.orm import WRITE_HOOKS, Meta, model_class
    from barq.stdlib2 import STDLIB_ALIASES, native_class, new_native
    from barq.web import BUILTIN_MIDDLEWARE
    g = i.builtins
    exc = BarqClass("PermissionException", "PermissionException", None, parent=i.classes["Exception"], native=True)
    i.classes["PermissionException"] = exc
    g.declare("PermissionException", exc, None, const=True)

    model = model_class(i)
    for cls_name, table, methods in (("Role", ROLES, ROLE_METHODS), ("Permission", PERMS, PERMISSION_METHODS)):
        cls = BarqClass(cls_name, cls_name, None, parent=model, native=True)
        m = Meta()
        m.cls, m.table, m.pk, m.fillable, m.guarded = cls, table, "id", ["name", "guard_name"], None
        m.hidden, m.casts, m.timestamps, m.connection, m.per_page, m.soft = [], {}, True, None, 15, False
        cls._orm_meta = m
        for name, (fn, lo, hi, names) in methods.items():
            cls.methods[name] = native(f"{cls_name}.{name}", fn, lo, hi, names, cls)
        for name, (fn, lo, hi, names) in statics(cls_name).items():
            f = native(f"{cls_name}.{name}", fn, lo, hi, names)
            f.late_static = True
            cls.statics[name] = PropInfo(name, None, "public", None, cls, is_static=True, const=True)
            cls.static_values[name] = f
        i.classes[cls_name] = cls
        g.declare(cls_name, cls, None, const=True)

    for name, (fn, lo, hi, names) in USER_METHODS.items():
        model.methods[name] = native(f"Model.{name}", fn, lo, hi, names, model)

    trait = BarqClass("HasRoles", "HasRoles", None, native=True)
    trait.kind = "trait"
    trait.decl = EmptyDecl()
    trait.module = i.module
    i.classes["HasRoles"] = trait
    g.declare("HasRoles", trait, None, const=True)

    g.declare("Permissions", module("Permissions", PERMISSIONS), None, const=True)
    native_class(i, "PermissionCache", None, {"forget": (lambda i2, a, n, this: forget(i2, n), 0, 0)})
    cstate(i).instances["barq.permissions.cache"] = new_native(i, "PermissionCache")

    if gate_check not in PRE_CHECKS:
        PRE_CHECKS.append(gate_check)
    if on_write not in WRITE_HOOKS:
        WRITE_HOOKS.append(on_write)
    for kind in ("role", "permission", "role_or_permission"):
        BUILTIN_MIDDLEWARE[kind] = NativeFunction(kind, mw_check(kind), 2, -1)
    STDLIB_ALIASES.update({"Permissions\\Role": "Role", "Permissions\\Permission": "Permission",
                           "Permissions\\HasRoles": "HasRoles", "Permissions\\Permissions": "Permissions",
                           "Permissions\\PermissionException": "PermissionException"})


# ===========================================================================
# CLI: barq permissions:*
# ===========================================================================

def cli_table(rows, headers):
    if not rows:
        return
    widths = [max(len(str(h)), *(len(str(r[k])) for r in rows)) for k, h in enumerate(headers)]
    print("  ".join(str(h).ljust(w) for h, w in zip(headers, widths)).rstrip())
    for r in rows:
        print("  ".join(str(v).ljust(w) for v, w in zip(r, widths)).rstrip())


def cli_list_roles(i):
    d = defs(i, None, "permissions:list-roles")
    if not d.roles:
        print("No roles yet. Create one: barq permissions:create-role admin")
        return
    counts = {}
    for r in sql(i, f'SELECT "role_id", COUNT(*) AS c FROM "{MODEL_ROLES}" GROUP BY "role_id"', [], None):
        counts[r["role_id"]] = r["c"]
    cli_table([(r["name"], r["guard_name"], len(d.role_perms.get(r["id"], ())), counts.get(r["id"], 0))
               for r in sorted(d.roles.values(), key=lambda r: (r["guard_name"], r["name"]))],
              ("Role", "Guard", "Permissions", "Users"))


def cli_list_permissions(i):
    d = defs(i, None, "permissions:list-permissions")
    if not d.perms:
        print('No permissions yet. Create one: barq permissions:create-permission "edit posts"')
        return
    cli_table([(p["name"], p["guard_name"],
                ", ".join(sorted(d.roles[r]["name"] for r, ps in d.role_perms.items() if p["id"] in ps and r in d.roles)))
               for p in sorted(d.perms.values(), key=lambda p: (p["guard_name"], p["name"]))],
              ("Permission", "Guard", "Roles"))


def cli_show_role(name, guard):
    def go(i):
        row = resolve(i, "Role", name, guard or default_guard(i), None, "permissions:show-role")
        d = defs(i, None)
        names = sorted(perm_names(d, d.role_perms.get(row["id"], set())))
        print(f'Role "{row["name"]}" (guard {row["guard_name"]})')
        sa = settings(i).get("super_admin_role")
        if sa == row["name"]:
            print("  super admin: passes every check")
        for p in names:
            print(f"  - {p}")
        if not names and sa != row["name"]:
            print("  (no permissions)")
    return go


def cli_create(cls_name, name, guard):
    def go(i):
        guard_ = guard or default_guard(i)
        row = find_def(defs(i, None, f"permissions:create-{kind_of(cls_name)}"), cls_name, name, guard_)
        if row is not None:
            print(f'The {kind_of(cls_name)} "{name}" already exists (guard {guard_})')
            return
        s_create(cls_name)(i, [name, guard_], None, i.classes[cls_name])
        print(f'Created {kind_of(cls_name)} "{name}" (guard {guard_})')
    return go


def cli_user(i, email, fname):
    from barq_auth.auth import guard_config, user_model
    from barq_framework.orm import mq_first, mq, new_mq
    from barq.stdlib2 import add_where
    cls = user_model(i, guard_config(i, default_guard(i), None)[1], None)
    q = new_mq(i, cls, None)
    add_where(i, ["email", email], None, mq(q).q, "AND", fname)
    user = mq_first(i, [], None, q)
    if user is None:
        throw(i, f"{fname}: no {cls.name} with the email {email}", None)
    return user


def cli_assign_role(email, role):
    def go(i):
        user = cli_user(i, email, "permissions:assign-role")
        u_assign_role(i, [role], None, user)
        print(f'Gave {email} the role "{role}"')
    return go


def cli_show_user(email):
    def go(i):
        user = cli_user(i, email, "permissions:show-user")
        d, rids, pids = assigned(i, user, None, None, "permissions:show-user")
        roles = sorted(d.roles[r]["name"] for r in rids if r in d.roles)
        print(f"{email}")
        print("  roles:       " + (", ".join(roles) or "(none)"))
        print("  direct:      " + (", ".join(sorted(perm_names(d, pids))) or "(none)"))
        print("  via roles:   " + (", ".join(sorted(perm_names(d, via_roles(d, rids)))) or "(none)"))
        if d.team_cols.get(MODEL_ROLES):
            teams = sql(i, f'SELECT "team_id", "role_id" FROM "{MODEL_ROLES}" WHERE "model_type" = ? AND "model_id" = ? '
                           'AND "team_id" IS NOT NULL ORDER BY "team_id"', [user.cls.fqn, key(i, user, None)], None)
            for t in teams:
                print(f'  team {t["team_id"]}:      {d.roles[t["role_id"]]["name"] if t["role_id"] in d.roles else "?"}')
        sa = settings(i).get("super_admin_role")
        if sa and sa in roles:
            print("  super admin: passes every check")
    return go


def cli_cache_reset(i):
    forget(i, None)
    print("Permission cache cleared.")


def cli(cmd, args):
    """-> (function taking the interpreter, error message)"""
    from barq.project import option
    guard, rest = option(args, "--guard")
    if guard is True:
        return None, "--guard needs a name"
    plain = {"permissions:list-roles": cli_list_roles, "permissions:list-permissions": cli_list_permissions,
             "permissions:cache-reset": cli_cache_reset}
    if cmd in plain:
        return plain[cmd], None
    need_args = {"permissions:show-role": 1, "permissions:create-role": 1, "permissions:create-permission": 1,
                 "permissions:assign-role": 2, "permissions:show-user": 1}
    usage = {"permissions:show-role": "<role> [--guard name]", "permissions:create-role": "<name> [--guard name]",
             "permissions:create-permission": '"<name>" [--guard name]', "permissions:assign-role": "<email> <role>",
             "permissions:show-user": "<email>"}
    if cmd not in need_args:
        return None, f"unknown command '{cmd}'"
    if len(rest) != need_args[cmd]:
        return None, f"usage: barq {cmd} {usage[cmd]}"
    if cmd == "permissions:show-role":
        return cli_show_role(rest[0], guard), None
    if cmd == "permissions:create-role":
        return cli_create("Role", rest[0], guard), None
    if cmd == "permissions:create-permission":
        return cli_create("Permission", rest[0], guard), None
    if cmd == "permissions:assign-role":
        return cli_assign_role(rest[0], rest[1]), None
    return cli_show_user(rest[0]), None
