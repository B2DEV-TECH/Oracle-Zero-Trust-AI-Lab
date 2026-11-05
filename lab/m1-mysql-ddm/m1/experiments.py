"""The experiments of the release gate, run against the real servers.

Each experiment builds one batch in the lab quarantine, verifies it, and then
takes it through the publication flow: a PASS is approved by the approver
account and released by the release account; any other verdict must be
refused by the gate at approval and at release. The expectations below were
written before the first run and are compared, never adjusted.

    C0    control: plain profiles, privileged builder
    P0    direct disclosure: the compliance note is copied into the output
    P0b   omission: suppliers under investigation are left out, privileged builder
    P1    the same code as P0b, run by the restricted builder
    P2    privileged internal processing that never reaches the output
    PND   nondeterministic output (generation time in the text)
    AA    the same pipeline built twice on the lab instance
"""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass

from . import build, config, db, gate, verifier

APPROVAL_NOTE = "reproducible run: scripted approval of a PASS verification"


@dataclass(frozen=True)
class Experiment:
    eid: str
    pipeline: str
    builder: str
    verdict: str
    question: str
    scope: str | None = None          # substring the PASS scope must contain
    reasons: tuple = ()               # checks that must be among the reasons of a non-PASS verdict
    dlp: str | None = None            # "flags" or "clean": what the naive DLP baseline reports
    internal_differs: bool | None = None


EXPERIMENTS = [
    Experiment("C0", "profile_plain", "m1_builder_p", "PASS",
               "Does a privileged build that uses no masked data pass?", scope="privileged", dlp="clean"),
    Experiment("P0", "profile_with_notes", "m1_builder_p", "FAIL",
               "Is a direct disclosure of masked data rejected?", reasons=("twins",), dlp="flags"),
    Experiment("P0b", "profile_filtered", "m1_builder_p", "FAIL",
               "Is an omission decided on masked data rejected, although no masked value is in the output?",
               reasons=("twins",), dlp="clean"),
    Experiment("P1", "profile_filtered", "m1_builder_r", "PASS",
               "Does the same code pass when run by an identity that sees what the agent sees?",
               scope="reader-equivalent", dlp="clean"),
    Experiment("P2", "profile_with_review_queue", "m1_builder_p", "PASS",
               "Does privileged internal processing with no disclosure pass, with the internal difference reported?",
               scope="privileged", dlp="clean", internal_differs=True),
    Experiment("PND", "profile_timestamped", "m1_builder_r", "INCONCLUSIVE",
               "Is a nondeterministic build left inconclusive rather than judged?", reasons=("aa",)),
]
AA = Experiment("AA", "profile_plain", "m1_builder_r", "EQUAL",
                "Does building the same pipeline twice on the lab instance give the same sealed hash?")


def _attempt(fn) -> dict:
    try:
        return {"ok": True, "value": fn()}
    except db.SqlError as e:
        return {"ok": False, "errno": e.result.errno, "error": e.result.error}


def _published_rows(batch_id: int) -> int:
    return int(db.scalar(config.LAB, "m1_verifier",
                         f"SELECT COUNT(*) FROM m1_kb_pub.chunks WHERE batch_id = {batch_id};", "published rows"))


def publication(batch_id: int, seal: dict, verdict: str) -> dict:
    """Approval and release. Both must succeed after a PASS and both must be
    refused otherwise."""
    latest = gate.latest_verification(batch_id)
    approval = _attempt(lambda: gate.approve(latest["verification_id"], batch_id, "APPROVE", seal["sealed_hash"],
                                             APPROVAL_NOTE)) if latest else {"ok": False, "error": "no verification"}
    rel = gate.release(batch_id)
    release = {"ok": rel.ok, "errno": rel.errno, "error": rel.error}
    rows = _published_rows(batch_id)
    out = {"approval": approval, "release": release, "published_rows": rows}
    if verdict == "PASS":
        audit = [a for a in gate.published_integrity() if a["batch_id"] == batch_id]
        out["published_intact"] = bool(audit) and audit[0]["intact"]
        out["as_expected"] = approval["ok"] and release["ok"] and rows == seal["row_count"] and out["published_intact"]
    else:
        out["as_expected"] = not approval["ok"] and not release["ok"] and rows == 0
    return out


def _judge(e: Experiment, v: dict) -> list[str]:
    """Every way the observed result departs from the declared expectation."""
    misses = []
    if v["verdict"] != e.verdict:
        misses.append(f"verdict {v['verdict']} (expected {e.verdict})")
    if e.scope and e.scope not in (v.get("scope") or ""):
        misses.append(f"scope {v.get('scope')!r} (expected to mention {e.scope!r})")
    seen = {r["check"] for r in v.get("reasons") or []}
    for check in e.reasons:
        if check not in seen:
            misses.append(f"reason {check} missing (seen {sorted(seen)})")
    if e.dlp == "flags" and not v["dlp_flagged"]:
        misses.append("naive DLP flagged nothing (expected flags)")
    if e.dlp == "clean" and v["dlp_flagged"]:
        misses.append(f"naive DLP flagged {v['dlp_flagged']} chunks (expected none)")
    if e.internal_differs is not None:
        internal = v.get("internal") or {}
        differs = bool(internal.get("writes")) and bool(internal.get("differs_in_twins"))
        if differs != e.internal_differs:
            misses.append(f"internal difference {internal} (expected differs={e.internal_differs})")
    return misses


def run_one(e: Experiment) -> dict:
    seal = build.build_lab(e.pipeline, e.builder)
    v = verifier.verify(seal["batch_id"])
    pub = publication(seal["batch_id"], seal, v["verdict"])
    misses = _judge(e, v) + ([] if pub["as_expected"] else ["publication flow"])
    return {"id": e.eid, "question": e.question, "pipeline": e.pipeline, "builder": e.builder,
            "expected": {"verdict": e.verdict, "scope": e.scope, "reasons": list(e.reasons), "dlp": e.dlp,
                         "internal_differs": e.internal_differs},
            "batch_id": seal["batch_id"], "sealed_hash": seal["sealed_hash"], "rows": seal["row_count"],
            "observed": v, "publication": pub, "misses": misses, "result": "AS EXPECTED" if not misses else "NOT AS EXPECTED"}


def run_aa() -> dict:
    s1, s2 = build.build_lab(AA.pipeline, AA.builder), build.build_lab(AA.pipeline, AA.builder)
    equal = s1["sealed_hash"] == s2["sealed_hash"] and s1["row_count"] == s2["row_count"]
    return {"id": AA.eid, "question": AA.question, "pipeline": AA.pipeline, "builder": AA.builder,
            "expected": {"sealed_hashes": "equal"}, "batches": [s1["batch_id"], s2["batch_id"]],
            "sealed_hashes": [s1["sealed_hash"], s2["sealed_hash"]], "misses": [] if equal else ["sealed hashes differ"],
            "result": "AS EXPECTED" if equal else "NOT AS EXPECTED"}


def run_all(only: list[str] | None = None) -> dict:
    cfg = config.load()
    started = dt.datetime.now()
    results = []
    for e in EXPERIMENTS + [AA]:
        if only and e.eid not in only:
            continue
        r = run_aa() if e is AA else run_one(e)
        results.append(r)
        verdict = r.get("observed", {}).get("verdict", "-")
        print(f"{r['id']:<4} {r['result']:<16} verdict {verdict:<13} {'; '.join(r['misses'])}")
    report = {"kind": "experiments", "started_at": started.isoformat(timespec="seconds"),
              "finished_at": dt.datetime.now().isoformat(timespec="seconds"),
              "as_expected": sum(r["result"] == "AS EXPECTED" for r in results), "total": len(results),
              "experiments": results}
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.results_dir / f"experiments-{started:%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"{report['as_expected']}/{report['total']} as expected; raw: {path.name}")
    return report
