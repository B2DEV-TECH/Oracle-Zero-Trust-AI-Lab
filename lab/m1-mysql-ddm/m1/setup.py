"""Deploys and removes M1 on one disposable instance, as the lab administrator.

Passwords are generated here, written to option files in the local secrets
folder and sent to the server through the client's stdin. They are never
printed and never passed on a command line.
"""

from __future__ import annotations

import re
import secrets
import string
from pathlib import Path

from . import config, db, fixtures

SQL_DIR = Path(__file__).resolve().parent.parent / "sql"
ACCOUNTS = ["m1_builder_p", "m1_builder_r", "m1_verifier", "m1_approver", "m1_release", "m1_agent", "m1_world"]
GATE_DEFINER = "m1_gate_def"


def _port(instance: str) -> int:
    text = config.load().cnf(instance, "root").read_text(encoding="ascii")
    return int(re.search(r"^port=(\d+)$", text, re.M).group(1))


def _write_cnf(path: Path, user: str, password: str, port: int) -> None:
    path.write_text(f"[client]\nuser={user}\npassword={password}\nhost=127.0.0.1\nport={port}\n", encoding="ascii")


def _script(name: str) -> str:
    return (SQL_DIR / name).read_text(encoding="utf-8")


def deploy(instance: str, with_gate: bool = True) -> None:
    cfg = config.load()
    if int(db.scalar(instance, "root",
                     "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME LIKE 'm1\\_%';")):
        raise SystemExit(f"{instance}: M1 is already deployed; run teardown first")
    port = _port(instance)
    alphabet = string.ascii_letters + string.digits
    creates = []
    for account in ACCOUNTS:
        password = "M1" + "".join(secrets.choice(alphabet) for _ in range(26))
        _write_cnf(cfg.cnf(instance, account), account, password, port)
        creates.append(f"CREATE USER '{account}'@'%' IDENTIFIED BY '{password}';")
    # The gate definer has no password and is locked; this option file exists
    # only so that a test can show that logging in as it is refused.
    _write_cnf(cfg.cnf(instance, GATE_DEFINER), GATE_DEFINER, "", port)
    creates.append(f"CREATE USER '{GATE_DEFINER}'@'%' ACCOUNT LOCK;")

    db.must(instance, "root", _script("10_core.sql"), "10_core.sql")
    db.must(instance, "root", "\n".join(creates), "accounts")
    if with_gate:
        db.must(instance, "root", _script("20_gate.sql"), "20_gate.sql")
        db.must(instance, "root", _script("30_grants.sql"), "30_grants.sql")
    db.must(instance, "root", fixtures.insert_sql(), "fixtures")
    print(f"{instance}: deployed ({'core + gate' if with_gate else 'core only'}), {len(ACCOUNTS)} accounts")


def teardown(instance: str) -> None:
    cfg = config.load()
    db.must(instance, "root", _script("99_teardown.sql"), "99_teardown.sql")
    for account in ACCOUNTS + [GATE_DEFINER]:
        cfg.cnf(instance, account).unlink(missing_ok=True)
    print(f"{instance}: M1 removed")
