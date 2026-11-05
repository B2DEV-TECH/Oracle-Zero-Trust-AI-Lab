"""Clearance negatives: each scenario perturbs the identity, role, object or
policy configuration, builds a batch and verifies it. The same perturbation
is applied to the lab and the shadow instance, so the verdict is driven by
the clearance checks and not by a preflight difference or drift. Every
scenario is reverted before the next one, and the run stops if the original
state is not restored.

The restricted builder runs the P1 code (profile_filtered); C12 gives the
privileged builder an administrative privilege and runs the C0 code.
Expectations (verdict and the checks that must be flagged) were written before
the first run; the full set of failing checks is reported as observed.

Anonymous accounts and proxy mappings are refused earlier, by the gate itself
(gate negatives G52 and G53), so they are not repeated here.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from dataclasses import dataclass

from . import build, clearance, config, db, gate, verifier
from .config import LAB, SHADOW
from .experiments import publication
from .setup import SQL_DIR

BR, BP = "m1_builder_r", "m1_builder_p"
P1_CODE, C0_CODE = "profile_filtered", "profile_plain"
VIEW = "m1_src.v_supplier_notes"
NOTE_COLUMN = "ALTER TABLE m1_src.suppliers MODIFY compliance_note VARCHAR(300) NULL MASKING POLICY {};"


def _policy_statement(name: str) -> str:
    """The exact CREATE statement of a contract policy, taken from 10_core.sql."""
    text = (SQL_DIR / "10_core.sql").read_text(encoding="utf-8")
    m = re.search(rf"CREATE MASKING POLICY {re.escape(name)}\(v\)\s+[^;]+;", text)
    if not m:
        raise KeyError(name)
    return m.group(0)


def _replace_note_policy(create: str) -> list[str]:
    # A bound policy cannot be dropped: park the column on another policy first.
    return [NOTE_COLUMN.format("m1_p_tax"), "DROP MASKING POLICY m1_p_note;", create, NOTE_COLUMN.format("m1_p_note")]


@dataclass(frozen=True)
class Scenario:
    cid: str
    title: str
    apply: tuple
    undo: tuple
    verdict: str
    targets: tuple               # clearance checks that must be flagged
    builder: str = BR
    pipeline: str = P1_CODE


SCENARIOS = [
    Scenario("C00", "Control: no perturbation", (), (), "PASS", ()),
    Scenario("C01", "Latent role: unmasking role granted to the restricted builder, not activated",
             ("GRANT 'm1_r_unmask' TO 'm1_builder_r'@'%';",), ("REVOKE 'm1_r_unmask' FROM 'm1_builder_r'@'%';",),
             "INCONCLUSIVE", ("C1",)),
    Scenario("C02", "activate_all_roles_on_login switched on",
             ("SET GLOBAL activate_all_roles_on_login = ON;",), ("SET GLOBAL activate_all_roles_on_login = OFF;",),
             "INCONCLUSIVE", ("C2",)),
    Scenario("C03", "Unmasking role made mandatory for every account",
             ("SET GLOBAL mandatory_roles = '`m1_r_unmask`@`%`';",), ("SET GLOBAL mandatory_roles = '';",),
             "INCONCLUSIVE", ("C2", "C3", "C7")),
    Scenario("C04", "DEFINER view over the source, owned by an account that reads unmasked data",
             (f"CREATE DEFINER = 'm1_world'@'%' SQL SECURITY DEFINER VIEW {VIEW} AS "
              "SELECT supplier_id, compliance_note FROM m1_src.suppliers;",), (f"DROP VIEW {VIEW};",),
             "INCONCLUSIVE", ("C3",)),
    Scenario("C05", "Policy gatekeeper changed to name the restricted builder",
             tuple(_replace_note_policy("CREATE MASKING POLICY m1_p_note(v) CASE WHEN "
                                        "CURRENT_USER_IN('m1_builder_r') THEN v ELSE '[RESTRICTED]' END;")),
             tuple(_replace_note_policy(_policy_statement("m1_p_note"))),
             "INCONCLUSIVE", ("C7",)),
    Scenario("C06", "Column UPDATE on a masked source column",
             ("GRANT UPDATE (risk_score) ON m1_src.suppliers TO 'm1_builder_r'@'%';",),
             ("REVOKE UPDATE (risk_score) ON m1_src.suppliers FROM 'm1_builder_r'@'%';",),
             "INCONCLUSIVE", ("C5", "W")),
    Scenario("C07", "ALTER on the source table",
             ("GRANT ALTER ON m1_src.suppliers TO 'm1_builder_r'@'%';",),
             ("REVOKE ALTER ON m1_src.suppliers FROM 'm1_builder_r'@'%';",),
             "INCONCLUSIVE", ("C5", "W")),
    Scenario("C08", "INSERT on the published table",
             ("GRANT INSERT ON m1_kb_pub.chunks TO 'm1_builder_r'@'%';",),
             ("REVOKE INSERT ON m1_kb_pub.chunks FROM 'm1_builder_r'@'%';",),
             "FAIL", ("W",)),
    Scenario("C09", "SELECT on the internal schema the agent cannot read",
             ("GRANT SELECT ON m1_ops.* TO 'm1_builder_r'@'%';",), ("REVOKE SELECT ON m1_ops.* FROM 'm1_builder_r'@'%';",),
             "INCONCLUSIVE", ("C5",)),
    Scenario("C10", "Global SELECT",
             ("GRANT SELECT ON *.* TO 'm1_builder_r'@'%';",), ("REVOKE SELECT ON *.* FROM 'm1_builder_r'@'%';",),
             "INCONCLUSIVE", ("C5",)),
    Scenario("C11", "Masked column moved to another existing policy (the gap of gate negative G50)",
             (NOTE_COLUMN.format("m1_p_tax"),), (NOTE_COLUMN.format("m1_p_note"),),
             "INCONCLUSIVE", ("C7",)),
    Scenario("C12", "Privileged builder holds the masking policy administration privilege",
             ("GRANT MANAGE_DATA_MASKING_POLICY ON *.* TO 'm1_builder_p'@'%';",),
             ("REVOKE MANAGE_DATA_MASKING_POLICY ON *.* FROM 'm1_builder_p'@'%';",),
             "FAIL", ("W",), builder=BP, pipeline=C0_CODE),
    # C03 with activate_mandatory_roles OFF: the role is no longer active at
    # login, but it is still granted to every account (SET ROLE ALL activates
    # it), so the verdict must not change.
    Scenario("C13", "Unmasking role made mandatory, with mandatory role activation switched off",
             ("SET GLOBAL activate_mandatory_roles = OFF;", "SET GLOBAL mandatory_roles = '`m1_r_unmask`@`%`';"),
             ("SET GLOBAL mandatory_roles = '';", "SET GLOBAL activate_mandatory_roles = ON;"),
             "INCONCLUSIVE", ("C2", "C3", "C7")),
]


def _state(instance: str) -> dict:
    snap = clearance.snapshot(instance)
    return {"observation": gate.observation_hash(instance), "bindings": snap["bindings"],
            "policies": snap["policies"], "globals": snap["globals"]}


def _apply(statements: tuple) -> list[dict]:
    """Applies the statements on both instances; reports per instance."""
    out = []
    for instance in (LAB, SHADOW):
        r = db.run(instance, "root", "\n".join(statements)) if statements else None
        out.append({"instance": instance, "ok": r is None or r.ok, "errno": r and r.errno, "error": r and r.error})
    return out


def run_one(s: Scenario, baseline: dict) -> dict:
    applied = _apply(s.apply)
    observed, pub, flagged = None, None, None
    try:
        if all(a["ok"] for a in applied):
            seal = build.build_lab(s.pipeline, s.builder)
            observed = verifier.verify(seal["batch_id"])
            ev = json.loads((config.load().results_dir / observed["evidence_file"]).read_text(encoding="utf-8"))
            flagged = sorted(c for c, r in ev["evidence"]["clearance"]["checks"].items() if not r["ok"])
            pub = publication(seal["batch_id"], seal, observed["verdict"])
    finally:
        undone = _apply(s.undo)
        restored = {i: _state(i) == baseline[i] for i in (LAB, SHADOW)}
    misses = []
    if not all(a["ok"] for a in applied):
        misses.append("perturbation not applied")
    else:
        if observed["verdict"] != s.verdict:
            misses.append(f"verdict {observed['verdict']} (expected {s.verdict})")
        missing = [c for c in s.targets if c not in flagged]
        if missing:
            misses.append(f"not flagged: {missing}")
        if not s.targets and flagged:
            misses.append(f"control flagged {flagged}")
        if not pub["as_expected"]:
            misses.append("publication flow")
    return {"id": s.cid, "title": s.title, "builder": s.builder, "pipeline": s.pipeline,
            "expected": {"verdict": s.verdict, "flagged": list(s.targets)},
            "applied": applied, "undone": undone, "restored": restored,
            "observed": observed, "flagged": flagged, "publication": pub,
            "misses": misses, "result": "AS EXPECTED" if not misses else "NOT AS EXPECTED"}


def run_all(only: list[str] | None = None) -> dict:
    cfg = config.load()
    started = dt.datetime.now()
    baseline = {i: _state(i) for i in (LAB, SHADOW)}
    if clearance.compare(clearance.snapshot(LAB), clearance.snapshot(SHADOW),
                         [f"{BR}@%", f"{BP}@%", clearance.AGENT, "m1_world@%"]):
        raise SystemExit("lab and shadow differ before the run; redeploy first")
    results = []
    for s in SCENARIOS:
        if only and s.cid not in only:
            continue
        r = run_one(s, baseline)
        results.append(r)
        verdict = (r["observed"] or {}).get("verdict", "-")
        print(f"{r['id']} {r['result']:<16} verdict {verdict:<13} flagged {r['flagged']} {'; '.join(r['misses'])}")
        if not all(r["restored"].values()):
            print(f"{r['id']}: original state NOT restored {r['restored']}; stopping")
            break
    report = {"kind": "clearance-negatives", "started_at": started.isoformat(timespec="seconds"),
              "finished_at": dt.datetime.now().isoformat(timespec="seconds"),
              "as_expected": sum(r["result"] == "AS EXPECTED" for r in results), "total": len(results),
              "state_restored": all(all(r["restored"].values()) for r in results), "scenarios": results}
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.results_dir / f"clearance-negatives-{started:%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(f"{report['as_expected']}/{report['total']} as expected; state restored: {report['state_restored']}; "
          f"raw: {path.name}")
    return report
