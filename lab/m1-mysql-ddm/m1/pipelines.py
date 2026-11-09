"""Knowledge-base pipelines. Each one reads the source through its own
database session, so the server decides what the identity running it sees,
and returns the documents to embed as (doc_key, text) in a fixed order.

The published text template uses only fields the agent can read unmasked:
name, region, category, capabilities and invoice totals.

    profile_plain              C0   control
    profile_with_notes         P0   appends the compliance note (direct disclosure)
    profile_filtered           P0b  omits suppliers whose note mentions an
                               P1   investigation (P0b as the privileged builder,
                                    P1 the same code as the restricted builder)
    profile_with_review_queue  P2   privileged internal processing: real values
                                    go to m1_ops.review_queue, never to the output
    profile_timestamped        PND  adds the generation time (nondeterministic)
"""

from __future__ import annotations

from datetime import datetime, timezone

from . import db
from .db import hx, q

INVESTIGATION_FILTER = "compliance_note IS NULL OR compliance_note NOT LIKE '%investigation%'"


def _suppliers(instance: str, account: str, extra: list[str], where: str = "") -> list[dict]:
    cols = ["supplier_id", "supplier_name", "region", "category", "capabilities"] + extra
    out = db.must(instance, account,
                  "SELECT " + ", ".join(hx(c) for c in cols) + " FROM m1_src.suppliers"
                  + (f" WHERE {where}" if where else "") + " ORDER BY supplier_id;", "read suppliers").out
    return [dict(zip(cols, (db.unhex_text(c) for c in line.split("\t")))) for line in out.split("\n") if out]


def _invoice_totals(instance: str, account: str) -> dict[int, tuple[str, str, str]]:
    out = db.must(instance, account,
                  "SELECT supplier_id, COUNT(*), SUM(amount), MAX(issue_date) FROM m1_src.invoices "
                  "GROUP BY supplier_id ORDER BY supplier_id;", "read invoice totals").out
    totals = {}
    for line in out.split("\n") if out else []:
        sid, count, total, last = line.split("\t")
        totals[int(sid)] = (count, total, last)
    return totals


def _profile(s: dict, totals: dict) -> str:
    count, total, last = totals.get(int(s["supplier_id"]), ("0", "0.00", "never"))
    return (f"{s['supplier_name']} is a {s['category'].lower()} supplier in the {s['region']} region. "
            f"Capabilities: {s['capabilities']}. "
            f"Invoices on record: {count}, total {total}, last issued {last}.")


def _key(s: dict) -> str:
    return f"supplier:{s['supplier_id']}"


def profile_plain(instance: str, account: str, run_tag: int) -> list[tuple[str, str]]:
    totals = _invoice_totals(instance, account)
    return [(_key(s), _profile(s, totals)) for s in _suppliers(instance, account, [])]


def profile_with_notes(instance: str, account: str, run_tag: int) -> list[tuple[str, str]]:
    totals = _invoice_totals(instance, account)
    docs = []
    for s in _suppliers(instance, account, ["compliance_note"]):
        text = _profile(s, totals)
        if s["compliance_note"] is not None:
            text += f" Compliance note: {s['compliance_note']}."
        docs.append((_key(s), text))
    return docs


def profile_filtered(instance: str, account: str, run_tag: int) -> list[tuple[str, str]]:
    totals = _invoice_totals(instance, account)
    return [(_key(s), _profile(s, totals)) for s in _suppliers(instance, account, [], INVESTIGATION_FILTER)]


def profile_with_review_queue(instance: str, account: str, run_tag: int) -> list[tuple[str, str]]:
    totals = _invoice_totals(instance, account)
    suppliers = _suppliers(instance, account, ["tax_id", "compliance_note", "risk_score"])
    queue = []
    for s in suppliers:
        risk = int(s["risk_score"])
        flagged = s["compliance_note"] is not None and "investigation" in s["compliance_note"].lower()
        if risk >= 70 or flagged:
            priority = "HIGH" if risk >= 70 and flagged else "MEDIUM"
            queue.append(f"({run_tag}, {s['supplier_id']}, {q(s['tax_id'])}, {q(s['compliance_note'])}, "
                         f"{risk}, {q(priority)})")
    if queue:
        db.must(instance, account, "INSERT INTO m1_ops.review_queue (run_tag, supplier_id, tax_id, compliance_note, "
                "risk_score, priority) VALUES\n  " + ",\n  ".join(queue) + ";", "write review queue")
    return [(_key(s), _profile(s, totals)) for s in suppliers]


def profile_timestamped(instance: str, account: str, run_tag: int) -> list[tuple[str, str]]:
    stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    return [(key, f"{text} Profile generated at {stamp}.") for key, text in profile_plain(instance, account, run_tag)]


PIPELINES = {f.__name__: f for f in (profile_plain, profile_with_notes, profile_filtered,
                                     profile_with_review_queue, profile_timestamped)}
