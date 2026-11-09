"""The source data as an identity sees it, and loading a world into the
shadow instance.

view() reads every source row through the account's own session, so masked
columns come back exactly as the server renders them for that identity.
"""

from __future__ import annotations

from . import db, fixtures, hashing
from .config import SHADOW
from .db import hx
from .fixtures import TABLES

View = dict[str, list[list]]  # table -> rows (values as text or None, TABLES column order)


def view(instance: str, account: str) -> View:
    out = {}
    for table, (pk, cols) in TABLES.items():
        res = db.must(instance, account, "SELECT " + ", ".join(hx(c) for c in cols)
                      + f" FROM m1_src.{table} ORDER BY {pk};", f"read {table}")
        out[table] = [[db.unhex_text(c) for c in line.split("\t")] for line in res.out.split("\n")] if res.out else []
    return out


def load(world: View, instance: str = SHADOW) -> None:
    """Replaces the source rows of the shadow instance. Never used on the lab."""
    if instance != SHADOW:
        raise ValueError("worlds are only loaded into the shadow instance")
    db.must(instance, "root", "START TRANSACTION;\nDELETE FROM m1_src.invoices;\nDELETE FROM m1_src.suppliers;\n"
            + fixtures.insert_sql(world["suppliers"], world["invoices"]) + "\nCOMMIT;", "load world")


def internal_output_hash(run_tag: int, instance: str = SHADOW) -> str:
    """Hash of what a run wrote to m1_ops (privileged internal output)."""
    out = db.must(instance, "root",
                  "SELECT supplier_id, " + ", ".join(hx(c) for c in ("tax_id", "compliance_note", "risk_score",
                                                                       "priority"))
                  + f" FROM m1_ops.review_queue WHERE run_tag = {run_tag} ORDER BY supplier_id;",
                  "read internal output").out
    return hashing.sha256_hex(out)
