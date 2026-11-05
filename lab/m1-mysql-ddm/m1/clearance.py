"""Identity clearance of the build account, and the M1-scoped configuration
snapshot the verifier compares between the lab and the shadow instance.

snapshot() only reads (grant tables, information_schema, SHOW CREATE TABLE)
and runs as the instance administrator, which is part of the trusted base.
Password hashes are never selected. evaluate() is pure, so every check can
be tested on synthetic snapshots.

Checks (C1-C6 decide whether the build identity is reader-equivalent; they
only set the scope of a PASS, never grant one):
    C1  roles: granted, latent (granted but not default) and nested roles
        stay within what the agent holds
    C2  global role activation: mandatory_roles empty, activate_all_roles_on_login OFF
        (activate_mandatory_roles is recorded, not decisive: see evaluate)
    C3  DEFINER objects: no view, routine or trigger reachable by the build
        identity runs as another account that can read the source
    C4  effective identity: one account row, no anonymous account, no proxy,
        and a live login resolves to the account with no active role
    C5  privileges: no global, dynamic or DDL privilege; every read is also
        a read the agent has
    C6  observed equivalence: the source read as the build identity equals
        the source read as the agent
    C7  masking contract and reader: declared policies and column bindings in
        force, agent holds no unmasking path (verdict INCONCLUSIVE if not)
    W   write surface: data writes only into quarantine or internal schemas
        the agent cannot read, and no other privilege beyond SELECT (DDL,
        routines, grants, policies, administration) (verdict FAIL if not)
"""

from __future__ import annotations

import re

from . import db, world
from .db import q

SYSTEM_SCHEMAS = ("mysql", "sys", "information_schema", "performance_schema")
AGENT = "m1_agent@%"
GATE_DEFINER = "m1_gate_def@%"
UNMASK_ROLE = "m1_r_unmask@%"
QUARANTINE_WRITES = {"m1_kb_q.batches", "m1_kb_q.chunks", "m1_ctl.seals"}
INTERNAL_SCHEMAS = {"m1_ops"}
READ_EXTRA = {"m1_kb_q.batches"}  # the builder's own batch rows; no source data
DATA_WRITES = {"INSERT", "UPDATE", "DELETE"}
ALLOWED_PRIVS = {"SELECT", "INSERT"}

# The masking contract as MySQL 26.7.0-commercial stores it (normalised text).
CONTRACT_POLICIES = {
    "m1_p_tax": ["(case when current_role_in(_utf8mb4'm1_r_unmask') then `v` "
                 "else concat(_utf8mb4'***-***-',right(`v`,4)) end)", "v"],
    "m1_p_note": ["(case when current_role_in(_utf8mb4'm1_r_unmask') then `v` else _utf8mb4'[RESTRICTED]' end)", "v"],
    "m1_p_risk": ["(case when current_role_in(_utf8mb4'm1_r_unmask') then `v` else 0 end)", "v"],
}
CONTRACT_BINDINGS = {"suppliers.tax_id": "m1_p_tax", "suppliers.compliance_note": "m1_p_note",
                     "suppliers.risk_score": "m1_p_risk"}
SOURCE_TABLES = ("suppliers", "invoices")
BINDING_RE = re.compile(r"^\s*`([^`]+)`.*MASKING POLICY `([^`]+)`", re.M)


# --------------------------------------------------------------------------
# Snapshot (read-only, administrator)
# --------------------------------------------------------------------------
def _rows(instance: str, sql: str, label: str) -> list[list[str]]:
    return db.must(instance, "root", sql, label).rows()


def _in(values) -> str:
    return "(" + ", ".join(q(v) for v in sorted(values)) + ")"


def _parse_roles(text: str) -> list[str]:
    roles = []
    for item in filter(None, (s.strip() for s in text.split(","))):
        item = item.replace("`", "").replace("'", "")
        roles.append(item if "@" in item else f"{item}@%")
    return roles


def _priv_columns(instance: str, table: str) -> list[str]:
    return [r[0] for r in _rows(instance, "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = "
                                f"'mysql' AND TABLE_NAME = {q(table)} AND COLUMN_NAME LIKE '%\\_priv' "
                                "ORDER BY ORDINAL_POSITION;", f"mysql.{table} columns")]


def _set_tokens(text: str) -> list[str]:
    return [t.strip().upper().replace(" ", "_") for t in text.split(",") if t.strip()]


def snapshot(instance: str) -> dict:
    g = _rows(instance, "SELECT @@GLOBAL.mandatory_roles, @@GLOBAL.activate_all_roles_on_login, "
                        "@@GLOBAL.activate_mandatory_roles;", "globals")[0]
    mandatory = _parse_roles(g[0])
    edges = [[f"{r[1]}@{r[0]}", f"{r[3]}@{r[2]}"] for r in
             _rows(instance, "SELECT FROM_HOST, FROM_USER, TO_HOST, TO_USER FROM mysql.role_edges;", "role edges")]
    users = {f"{r[0]}@{r[1]}" for r in _rows(instance, "SELECT User, Host FROM mysql.user WHERE User LIKE 'm1\\_%' "
                                             "OR User = '';", "m1 accounts")}
    users |= {UNMASK_ROLE} | set(mandatory)
    while True:  # every role reachable from an M1 account
        more = {role for role, grantee in edges if grantee in users} - users
        if not more:
            break
        users |= more
    names = {u.rsplit("@", 1)[0] for u in users}

    accounts = {u: {"privileges": set(), "proxies": []} for u in users}

    def add(user, host, token):
        accounts.setdefault(f"{user}@{host}", {"privileges": set(), "proxies": []})["privileges"].add(token)

    ucols = _priv_columns(instance, "user")
    for r in _rows(instance, f"SELECT User, Host, {', '.join(ucols)}, account_locked FROM mysql.user "
                   f"WHERE User IN {_in(names)};", "user privileges"):
        for col, val in zip(ucols, r[2:-1]):
            if val == "Y":
                add(r[0], r[1], f"global|*|{col[:-5].upper()}")
        accounts[f"{r[0]}@{r[1]}"]["locked"] = r[-1]
    for r in _rows(instance, f"SELECT USER, HOST, PRIV, WITH_GRANT_OPTION FROM mysql.global_grants "
                   f"WHERE USER IN {_in(names)};", "dynamic privileges"):
        add(r[0], r[1], f"dynamic|*|{r[2].upper()}")
    dcols = _priv_columns(instance, "db")
    for r in _rows(instance, f"SELECT User, Host, Db, {', '.join(dcols)} FROM mysql.db WHERE User IN {_in(names)};",
                   "schema privileges"):
        for col, val in zip(dcols, r[3:]):
            if val == "Y":
                add(r[0], r[1], f"db|{r[2]}|{col[:-5].upper()}")
    for r in _rows(instance, "SELECT User, Host, Db, Table_name, Table_priv FROM mysql.tables_priv "
                   f"WHERE User IN {_in(names)};", "table privileges"):
        for token in _set_tokens(r[4]):
            add(r[0], r[1], f"table|{r[2]}.{r[3]}|{token}")
    for r in _rows(instance, "SELECT User, Host, Db, Table_name, Column_name, Column_priv FROM mysql.columns_priv "
                   f"WHERE User IN {_in(names)};", "column privileges"):
        for token in _set_tokens(r[5]):
            add(r[0], r[1], f"column|{r[2]}.{r[3]}.{r[4]}|{token}")
    for r in _rows(instance, "SELECT User, Host, Db, Routine_name, Proc_priv FROM mysql.procs_priv "
                   f"WHERE User IN {_in(names)};", "routine privileges"):
        for token in _set_tokens(r[4]):
            add(r[0], r[1], f"routine|{r[2]}.{r[3]}|{token}")
    for r in _rows(instance, "SELECT Host, User, Proxied_host, Proxied_user FROM mysql.proxies_priv "
                   f"WHERE User IN {_in(names)} OR Proxied_user IN {_in(names)};", "proxies"):
        if r[1] == "root" and r[3] == "":
            continue  # the default ''@'' proxy grant of root
        for key in (f"{r[1]}@{r[0]}", f"{r[3]}@{r[2]}"):
            if key in accounts:
                accounts[key]["proxies"].append(f"{r[1]}@{r[0]}->{r[3]}@{r[2]}")
    defaults = {}
    for r in _rows(instance, "SELECT HOST, USER, DEFAULT_ROLE_HOST, DEFAULT_ROLE_USER FROM mysql.default_roles;",
                   "default roles"):
        defaults.setdefault(f"{r[1]}@{r[0]}", []).append(f"{r[3]}@{r[2]}")

    excluded = _in(SYSTEM_SCHEMAS)
    objects = []
    for r in _rows(instance, "SELECT TABLE_SCHEMA, TABLE_NAME, DEFINER, SECURITY_TYPE FROM information_schema.VIEWS "
                   f"WHERE TABLE_SCHEMA NOT IN {excluded};", "views"):
        objects.append({"kind": "view", "object": f"{r[0]}.{r[1]}", "definer": r[2], "security": r[3]})
    for r in _rows(instance, "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, DEFINER, SECURITY_TYPE FROM "
                   f"information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN {excluded};", "routines"):
        objects.append({"kind": "routine", "object": f"{r[0]}.{r[1]}", "definer": r[2], "security": r[3]})
    for r in _rows(instance, "SELECT TRIGGER_SCHEMA, TRIGGER_NAME, EVENT_OBJECT_TABLE, DEFINER FROM "
                   f"information_schema.TRIGGERS WHERE TRIGGER_SCHEMA NOT IN {excluded};", "triggers"):
        objects.append({"kind": "trigger", "object": f"{r[0]}.{r[2]}", "name": r[1], "definer": r[3],
                        "security": "DEFINER"})

    tables, bindings = {}, {}
    for table in SOURCE_TABLES:
        ddl = db.must(instance, "root", f"SHOW CREATE TABLE m1_src.{table};", f"show create {table}").out
        ddl = re.sub(r" AUTO_INCREMENT=\d+", "", ddl.split("\t", 1)[1])
        tables[table] = ddl
        for col, policy in BINDING_RE.findall(ddl):
            bindings[f"{table}.{col}"] = policy
    wanted = set(CONTRACT_POLICIES) | set(bindings.values())
    policies = {}
    for r in _rows(instance, "SELECT policy_name, HEX(expression), HEX(argument) FROM mysql.column_masking_policies "
                   f"WHERE policy_name IN {_in(wanted)} OR policy_name LIKE 'm1\\_%';", "policies"):
        policies[r[0]] = [bytes.fromhex(r[1]).decode("utf-8"), bytes.fromhex(r[2]).decode("utf-8")]

    for acc in accounts.values():
        acc["privileges"] = sorted(acc["privileges"])
        acc["proxies"] = sorted(acc["proxies"])
    return {
        "globals": {"mandatory_roles": mandatory, "activate_all_roles_on_login": g[1],
                    "activate_mandatory_roles": g[2]},
        "anonymous_accounts": sorted(u for u in accounts if u.startswith("@")),
        "edges": sorted(edges),
        "defaults": {k: sorted(v) for k, v in sorted(defaults.items()) if k in accounts},
        "accounts": dict(sorted(accounts.items())),
        "objects": sorted(objects, key=lambda o: (o["kind"], o["object"], o.get("name", ""))),
        "tables": tables,
        "bindings": dict(sorted(bindings.items())),
        "policies": dict(sorted(policies.items())),
    }


# --------------------------------------------------------------------------
# Live checks (log in as the identities)
# --------------------------------------------------------------------------
def whoami(instance: str, account: str) -> dict:
    r = db.run(instance, account, "SELECT CURRENT_USER(), CURRENT_ROLE();")
    if not r.ok:
        return {"login": False, "error": f"{r.errno} {r.error}"}
    user, role = r.out.split("\t")
    return {"login": True, "current_user": user, "current_role": role}


def live(instance: str, builder: str) -> dict:
    account = builder.rsplit("@", 1)[0]
    facts = {"builder": whoami(instance, account), "agent": whoami(instance, AGENT.rsplit("@", 1)[0])}
    try:
        facts["views_equal"] = world.view(instance, account) == world.view(instance, AGENT.rsplit("@", 1)[0])
    except db.SqlError as e:
        facts["views_equal"] = False
        facts["view_error"] = str(e)
    return facts


# --------------------------------------------------------------------------
# Evaluation (pure)
# --------------------------------------------------------------------------
def closure(snap: dict, account: str) -> set[str]:
    """Every role the account could activate: granted (directly or nested)
    and mandatory roles."""
    found, todo = set(), [account] + list(snap["globals"]["mandatory_roles"])
    found |= set(snap["globals"]["mandatory_roles"])
    while todo:
        cur = todo.pop()
        for role, grantee in snap["edges"]:
            if grantee == cur and role not in found:
                found.add(role)
                todo.append(role)
    return found


def potential(snap: dict, account: str) -> set[str]:
    privs = set(snap["accounts"].get(account, {}).get("privileges", []))
    for role in closure(snap, account):
        privs |= set(snap["accounts"].get(role, {}).get("privileges", []))
    return privs


def _parts(token: str) -> tuple[str, str, str]:
    scope, obj, priv = token.split("|")
    return scope, obj, priv


def can(privs: set[str], priv: str, obj: str) -> bool:
    """obj is 'schema.table' or 'schema.routine'."""
    schema = obj.split(".", 1)[0]
    return bool({f"global|*|{priv}", f"db|{schema}|{priv}", f"table|{obj}|{priv}", f"routine|{obj}|{priv}"} & privs)


def reads_any(privs: set[str], obj: str) -> bool:
    """True if the account can read any part of a table, or of any table in a
    schema when obj has no table part."""
    if "." not in obj:
        return any(_parts(t)[2] == "SELECT" and (_parts(t)[0] == "global" or _parts(t)[1].split(".")[0] == obj)
                   for t in privs)
    return can(privs, "SELECT", obj) or any(t.startswith(f"column|{obj}.") and t.endswith("|SELECT") for t in privs)


def _user(definer: str) -> str:
    return definer.rsplit("@", 1)[0]


def _reads_source(privs: set[str]) -> bool:
    return any(_parts(t)[2] == "SELECT" and (_parts(t)[0] == "global" or _parts(t)[1].split(".")[0] == "m1_src")
               for t in privs)


def reachable_definer_objects(snap: dict, account: str) -> list[dict]:
    privs = potential(snap, account)
    me = _user(account)
    found = []
    for o in snap["objects"]:
        if o["security"] != "DEFINER" or _user(o["definer"]) == me:
            continue
        if o["kind"] == "view":
            reach = reads_any(privs, o["object"])
        elif o["kind"] == "routine":
            reach = can(privs, "EXECUTE", o["object"])
        else:
            reach = any(can(privs, p, o["object"]) for p in DATA_WRITES)
        if reach:
            found.append(o)
    return found


def evaluate(snap: dict, builder: str, live_facts: dict) -> dict:
    agent_roles = closure(snap, AGENT)
    agent_privs = potential(snap, AGENT)
    roles = closure(snap, builder)
    privs = potential(snap, builder)
    checks = {}

    granted = sorted(role for role, grantee in snap["edges"] if grantee == builder)
    defaults = snap["defaults"].get(builder, [])
    checks["C1"] = {"ok": roles <= agent_roles, "granted": granted, "default": defaults,
                    "latent": sorted(set(granted) - set(defaults)), "closure": sorted(roles),
                    "unmask_reachable": UNMASK_ROLE in roles}

    # activate_mandatory_roles (default ON) activates the mandatory roles at
    # login. It is recorded but does not decide C2: with no mandatory role it
    # has no effect, and switching it off leaves a mandatory role granted to
    # every account, which SET ROLE ALL still activates.
    g = snap["globals"]
    checks["C2"] = {"ok": not g["mandatory_roles"] and str(g["activate_all_roles_on_login"]) in ("0", "OFF"),
                    "mandatory_roles": g["mandatory_roles"],
                    "activate_all_roles_on_login": g["activate_all_roles_on_login"],
                    "activate_mandatory_roles": g["activate_mandatory_roles"]}

    gate_privs = potential(snap, GATE_DEFINER)
    gate_clean = not _reads_source(gate_privs) and not closure(snap, GATE_DEFINER)
    flagged = [o for o in reachable_definer_objects(snap, builder)
               if not (gate_clean and o["definer"] == GATE_DEFINER)]
    checks["C3"] = {"ok": not flagged, "objects": flagged, "gate_definer_reads_source": not gate_clean}

    name = _user(builder)
    rows = sorted(a for a in snap["accounts"] if _user(a) == name)
    who = live_facts.get("builder", {})
    checks["C4"] = {"ok": rows == [builder] and not snap["anonymous_accounts"]
                    and not snap["accounts"].get(builder, {}).get("proxies")
                    and who.get("login") is True and who.get("current_user") == builder
                    and who.get("current_role") == "NONE",
                    "account_rows": rows, "anonymous_accounts": snap["anonymous_accounts"],
                    "proxies": snap["accounts"].get(builder, {}).get("proxies", []), "live": who}

    forbidden = sorted(t for t in privs if _parts(t)[0] in ("global", "dynamic") or _parts(t)[2] not in ALLOWED_PRIVS)
    extra_reads = []
    for t in privs:
        scope, obj, priv = _parts(t)
        if priv != "SELECT":
            continue
        target = obj if scope != "column" else obj.rsplit(".", 1)[0]
        if scope == "db":
            covered = bool({f"db|{obj}|SELECT", "global|*|SELECT"} & agent_privs)
        else:
            covered = target in READ_EXTRA or reads_any(agent_privs, target)
        if not covered:
            extra_reads.append(t)
    checks["C5"] = {"ok": not forbidden and not extra_reads, "forbidden": forbidden,
                    "reads_beyond_agent": sorted(extra_reads)}

    checks["C6"] = {"ok": live_facts.get("views_equal") is True, "views_equal": live_facts.get("views_equal")}

    agent_who = live_facts.get("agent", {})
    policy_ok = all(snap["policies"].get(p) == v for p, v in CONTRACT_POLICIES.items())
    binding_ok = snap["bindings"] == CONTRACT_BINDINGS
    checks["C7"] = {"ok": policy_ok and binding_ok and UNMASK_ROLE not in agent_roles
                    and agent_who.get("current_role") == "NONE",
                    "policies_match_contract": policy_ok, "bindings_match_contract": binding_ok,
                    "bindings": snap["bindings"], "agent_unmask_reachable": UNMASK_ROLE in agent_roles,
                    "agent_live": agent_who}

    violations = []
    for t in sorted(privs):
        scope, obj, priv = _parts(t)
        if priv == "SELECT":
            continue  # reads are C5's concern
        if priv not in DATA_WRITES or scope in ("global", "dynamic"):
            violations.append(t)  # DDL, routines, grants, policies, administration
            continue
        target = obj.rsplit(".", 1)[0] if scope == "column" else obj
        schema = target.split(".", 1)[0]
        if scope == "db":
            if schema not in INTERNAL_SCHEMAS or reads_any(agent_privs, schema):
                violations.append(t)
        elif not (target in QUARANTINE_WRITES or schema in INTERNAL_SCHEMAS) or reads_any(agent_privs, target):
            violations.append(t)
    checks["W"] = {"ok": not violations, "violations": violations}

    return {"builder": builder, "checks": checks,
            "reader_equivalent": all(checks[c]["ok"] for c in ("C1", "C2", "C3", "C4", "C5", "C6")),
            "contract_ok": checks["C7"]["ok"], "write_ok": checks["W"]["ok"]}


def compare(lab: dict, shadow: dict, accounts: list[str]) -> list[str]:
    """Keys on which the shadow instance does not replicate the lab, for the
    identities whose behaviour the verifier replays."""
    diffs = [k for k in ("globals", "anonymous_accounts", "tables", "bindings", "policies") if lab[k] != shadow[k]]
    for acc in accounts:
        for label, fn in (("closure", closure), ("privileges", potential)):
            if sorted(fn(lab, acc)) != sorted(fn(shadow, acc)):
                diffs.append(f"{acc}:{label}")
        if lab["defaults"].get(acc) != shadow["defaults"].get(acc):
            diffs.append(f"{acc}:defaults")
        if lab["accounts"].get(acc, {}).get("proxies") != shadow["accounts"].get(acc, {}).get("proxies"):
            diffs.append(f"{acc}:proxies")
        if ([o["object"] for o in reachable_definer_objects(lab, acc)]
                != [o["object"] for o in reachable_definer_objects(shadow, acc)]):
            diffs.append(f"{acc}:definer_objects")
        rows = (sorted(a for a in lab["accounts"] if _user(a) == _user(acc)),
                sorted(a for a in shadow["accounts"] if _user(a) == _user(acc)))
        if rows[0] != rows[1]:
            diffs.append(f"{acc}:account_rows")
    return diffs
