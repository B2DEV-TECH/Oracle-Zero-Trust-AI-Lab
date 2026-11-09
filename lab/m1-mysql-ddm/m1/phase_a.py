"""Phase A control: the gate negatives on a deployment that keeps the gate's
tables, functions, grants, accounts and release interface, without its
enforcement (no triggers, and a release procedure that checks nothing; see
setup.control_gate_sql). It measures what the gate adds on top of plain
privileges, the account lock and the table keys.

Not every scenario means something without the gate. The prediction for each
one was written here before the control first ran; the report compares it
with what happened and is never adjusted afterwards. Outcome classes:

  met             the expectation is met without the gate (privileges, the
                  account lock, a positive control, the integrity audit)
  other           refused, by a mechanism other than the expected one
  succeeded       the action the gate refuses goes through
  not executable  the scenario cannot run as written without the gate
  not comparable  it runs, but its result means nothing without the gate

The gate's added refusals are the comparable scenarios that succeeded
without the gate and were refused with it, in a gate run on the same kind
of deployment (phase B).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from collections import Counter
from pathlib import Path

from . import config, db, negatives
from .config import LAB

MET, OTHER, SUCCEEDED, NOT_EXECUTABLE, NOT_COMPARABLE = (
    "met", "other", "succeeded", "not executable", "not comparable")

# Scenarios whose refused action is performed by the lab administrator. The
# administrator can drop the triggers, so for these the gate is a guardrail,
# not a boundary (trusted computing base).
ADMINISTRATOR = {"G07", "G14", "G15", "G16", "G17", "G18", "G37", "G38", "G42", "G43", "G45", "G46", "G54"}

_GRANTS = (MET, None, "refused by privileges (error 1142) with or without the gate")
_EXECUTE = (MET, None, "refused by the EXECUTE grant on the release procedure (error 1370)")
_GATE = (SUCCEEDED, None, "refused only by the gate's triggers or release checks")
_ADMIN = (SUCCEEDED, None, "refused only by the gate's triggers, which the administrator can drop")
_DROPS_TRIGGER = (NOT_EXECUTABLE, 1360, "drops a gate trigger, which does not exist without the gate; "
                                        "G14 is the comparable administrator edit")

# sid -> (predicted class, error number the prediction names, what the result shows)
PREDICTIONS: dict[str, tuple[str, int | None, str]] = {
    "G01": _GATE, "G02": _GATE,
    "G03": _GRANTS, "G04": _GRANTS, "G05": _GRANTS, "G06": _GRANTS,
    "G07": _ADMIN,
    "G08": _GATE, "G09": _GATE, "G10": _GATE, "G11": _GATE, "G12": _GATE,
    "G13": _GRANTS,
    "G14": _ADMIN, "G15": _ADMIN, "G16": _ADMIN, "G17": _ADMIN,
    "G18": _DROPS_TRIGGER,
    "G19": _GATE, "G20": _GATE, "G21": _GATE, "G22": _GATE, "G23": _GATE, "G24": _GATE, "G25": _GATE,
    "G26": _GRANTS, "G27": _GRANTS,
    "G28": _EXECUTE, "G29": _EXECUTE,
    "G30": _GATE, "G31": _GATE,
    "G32": _GRANTS,
    "G33": _GATE,
    "G34": (MET, None, "refused by the account lock (error 3118) with or without the gate"),
    "G35": _GRANTS, "G36": _GRANTS,
    "G37": _ADMIN, "G38": _ADMIN,
    "G39": (MET, None, "the release interface works without the gate"),
    "G40": (NOT_COMPARABLE, None, "the sealed hash is computed by a gate trigger; without it the seal has none"),
    "G41": (OTHER, 1062, "refused by the primary key of the published table; the gate gives the clearer refusal"),
    "G42": _ADMIN, "G43": _ADMIN,
    "G44": _GRANTS,
    "G45": _ADMIN,
    "G46": _DROPS_TRIGGER,
    "G47": _GATE, "G48": _GATE, "G49": _GATE,
    # G50 was the known gap (met: released with and without the gate) until the
    # release procedure refused a source table altered after the batch was opened.
    "G50": _GATE,
    "G51": _GATE, "G52": _GATE, "G53": _GATE,
    "G54": (MET, None, "detective only: the audit finds the truncation; neither deployment prevents it"),
    "G55": _GATE,
    "G56": (MET, None, "positive control: a binding moved and moved back before the batch is opened "
                       "does not block its release"),
    "G57": _GATE,
}


def observed_class(row: dict) -> str:
    """Outcome class of one scenario of a gate-negatives run on the control."""
    seen = row["observed"]
    if row["result"] == "PASS":
        return MET
    if seen == "ok":
        return SUCCEEDED
    if seen.startswith("setup failed"):
        return NOT_EXECUTABLE
    if seen.startswith("ERROR"):
        return OTHER
    return NOT_COMPARABLE


def held(row: dict) -> bool:
    predicted, errno, _ = PREDICTIONS[row["id"]]
    return observed_class(row) == predicted and (errno is None or f"ERROR {errno} " in row["observed"])


def compare(control: dict, gate_run: dict) -> dict:
    gate_by_id = {r["id"]: r for r in gate_run["scenarios"]}
    if set(gate_by_id) != {r["id"] for r in control["scenarios"]} or set(gate_by_id) != set(PREDICTIONS):
        raise ValueError("the control run, the gate run and the predictions do not cover the same scenarios")
    rows = []
    for r in control["scenarios"]:
        predicted, errno, note = PREDICTIONS[r["id"]]
        g = gate_by_id[r["id"]]
        rows.append(dict(id=r["id"], category=r["category"], title=r["title"], expected=r["expected"],
                         administrator=r["id"] in ADMINISTRATOR, predicted=predicted, predicted_errno=errno,
                         observed_class=observed_class(r), prediction_held=held(r), shows=note,
                         control_observed=r["observed"], gate_observed=g["observed"], gate_result=g["result"]))
    comparable = [x for x in rows if x["observed_class"] not in (NOT_EXECUTABLE, NOT_COMPARABLE)]
    added = [x for x in comparable if x["observed_class"] == SUCCEEDED and x["gate_result"] == "PASS"]
    summary = dict(
        total=len(rows),
        predictions_held=sum(x["prediction_held"] for x in rows),
        by_class=dict(Counter(x["observed_class"] for x in rows)),
        comparable=len(comparable),
        gate_met=sum(x["gate_result"] == "PASS" for x in rows),
        gate_adds=len(added),
        gate_adds_non_administrator=sum(not x["administrator"] for x in added),
        gate_adds_administrator=sum(x["administrator"] for x in added),
        gate_adds_ids=[x["id"] for x in added],
        not_comparable_ids=[x["id"] for x in rows if x["observed_class"] in (NOT_EXECUTABLE, NOT_COMPARABLE)],
    )
    return dict(summary=summary, scenarios=rows)


def deployment(instance: str = LAB) -> dict:
    """What is deployed: gate triggers, routines, and whether the release procedure checks anything."""
    triggers = int(db.scalar(instance, "root", "SELECT COUNT(*) FROM information_schema.TRIGGERS "
                             "WHERE TRIGGER_SCHEMA IN ('m1_kb_q', 'm1_ctl', 'm1_kb_pub');", "triggers"))
    routines = db.must(instance, "root", "SELECT CONCAT(ROUTINE_TYPE, ' ', ROUTINE_NAME) FROM information_schema.ROUTINES "
                       "WHERE ROUTINE_SCHEMA = 'm1_ctl' ORDER BY 1;", "routines").out.split("\n")
    # The whole definition (db.scalar would keep only its last line).
    release = db.must(instance, "root", "SELECT ROUTINE_DEFINITION FROM information_schema.ROUTINES "
                      "WHERE ROUTINE_SCHEMA = 'm1_ctl' AND ROUTINE_NAME = 'release_batch';", "release procedure").out
    return dict(triggers=triggers, routines=routines, release_checks="SIGNAL SQLSTATE" in release,
                release_definition_sha256=hashlib.sha256(release.encode("utf-8")).hexdigest())


def releases(instance: str = LAB) -> dict:
    """Evidence that the control released batches: release records and published rows at the end of the run."""
    out = db.must(instance, "root", "SELECT (SELECT COUNT(*) FROM m1_ctl.releases), "
                  "(SELECT COUNT(*) FROM m1_ctl.releases WHERE verification_id = 0 OR approval_id = 0), "
                  "(SELECT COUNT(*) FROM m1_kb_pub.chunks);", "releases").out
    records, without_approval_chain, published = (int(x) for x in out.split("\t"))
    return dict(release_records=records, records_without_verification_or_approval=without_approval_chain,
                published_rows=published)


def run(gate_result: str) -> dict:
    cfg = config.load()
    gate_path = Path(gate_result) if Path(gate_result).is_absolute() else cfg.results_dir / gate_result
    gate_run = json.loads(gate_path.read_text(encoding="utf-8"))
    before = deployment()
    if before["triggers"] or before["release_checks"] or "PROCEDURE release_batch" not in before["routines"]:
        raise SystemExit("lab: this is not the phase A control deployment; teardown, then deploy --control")
    control = negatives.run_all()
    report = dict(kind="phase-a-control", at=dt.datetime.now().isoformat(timespec="seconds"),
                  deployment=before, control_negatives_at=control["at"],
                  control_observation_state_restored=control["observation_state_restored"],
                  gate_result=gate_path.name, gate_negatives_at=gate_run["at"],
                  releases_at_end=releases(), **compare(control, gate_run))
    path = cfg.results_dir / f"phase-a-control-{dt.datetime.now():%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for x in report["scenarios"]:
        flag = "" if x["prediction_held"] else "  PREDICTION MISSED"
        print(f"{x['id']} {x['observed_class']:<15} predicted {x['predicted']:<15}{flag}")
    s = report["summary"]
    print(f"control: {s['by_class']}; predictions held {s['predictions_held']}/{s['total']}")
    print(f"gate adds a refusal in {s['gate_adds']} of {s['comparable']} comparable scenarios "
          f"({s['gate_adds_non_administrator']} non-administrator, {s['gate_adds_administrator']} administrator); "
          f"raw: {path.name}")
    return report
