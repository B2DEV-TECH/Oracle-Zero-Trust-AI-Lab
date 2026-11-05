"""Negative tests of the publication gate, run against the real server.

Each scenario prepares state through the normal accounts, then performs one
final action whose outcome is compared with a fixed expectation. The
expectations were written before the gate existed; run against a core-only
deployment, they fail.

These scenarios test enforcement, not judgment: verification rows are
written directly under the verifier account with whatever verdict the
scenario needs. Whether a verdict is correct is the verifier's job, tested by
the experiments.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from typing import Callable

from . import config, db, gate
from .config import LAB
from .setup import SQL_DIR

CODE = hashlib.sha256(b"m1-gate-test-pipeline").hexdigest()
OTHER_CODE = hashlib.sha256(b"m1-some-other-pipeline").hexdigest()
ZERO = "0" * 64
BR, BP = "m1_builder_r", "m1_builder_p"


def _embedding(seed: int) -> bytes:
    return struct.pack("<384f", *[((seed * 31 + i * 7) % 97) / 97.0 for i in range(384)])


def _chunks(n: int, tag: str) -> list[tuple[int, str, str, bytes]]:
    return [(i, f"gate-test:{tag}:{i}", f"Gate test chunk {i} of {tag}", _embedding(i)) for i in range(1, n + 1)]


def _gate_statement(name: str) -> str:
    """The exact CREATE statement of a gate trigger, taken from 20_gate.sql."""
    text = (SQL_DIR / "20_gate.sql").read_text(encoding="utf-8")
    for stmt in text.split("//"):
        if re.search(rf"TRIGGER {re.escape(name)} ", stmt):
            return stmt[stmt.index("CREATE DEFINER"):].strip()
    raise KeyError(name)


# --------------------------------------------------------------------------
# State builders (every step must succeed)
# --------------------------------------------------------------------------
def open_with_chunks(builder: str = BR, n: int = 2, code: str = CODE) -> int:
    batch = gate.open_batch(builder, "gate-test", code)
    gate.add_chunks(builder, batch, _chunks(n, f"b{batch}"))
    return batch


def sealed(builder: str = BR, n: int = 2) -> tuple[int, dict]:
    batch = open_with_chunks(builder, n)
    return batch, gate.seal(builder, batch)


def verified(verdict: str = "PASS", builder: str = BR) -> tuple[int, dict, int]:
    batch, seal = sealed(builder)
    vid = gate.record_verification(batch, verdict, seal["sealed_hash"], gate.observation_hash(), CODE, ZERO, ZERO)
    return batch, seal, vid


def approved(builder: str = BR) -> tuple[int, dict, int, int]:
    batch, seal, vid = verified("PASS", builder)
    aid = gate.approve(vid, batch, "APPROVE", seal["sealed_hash"], "gate test approval")
    return batch, seal, vid, aid


def root_bypass_update(batch: int) -> None:
    """The administrator drops the guard trigger, edits content, restores the trigger."""
    db.must(LAB, "root", "\n".join([
        "DROP TRIGGER m1_kb_q.chunks_bu;",
        f"UPDATE m1_kb_q.chunks SET content = CONCAT(content, ' [edited]') WHERE batch_id = {batch} AND chunk_no = 1;",
        "DELIMITER //", _gate_statement("m1_kb_q.chunks_bu") + "//", "DELIMITER ;",
    ]), "admin bypass")


# --------------------------------------------------------------------------
# Scenarios
# --------------------------------------------------------------------------
@dataclass
class Scenario:
    sid: str
    category: str
    title: str
    expect: tuple
    fn: Callable


SCENARIOS: list[Scenario] = []


def scenario(sid: str, category: str, title: str, expect: tuple):
    def register(fn):
        SCENARIOS.append(Scenario(sid, category, title, expect, fn))
        return fn
    return register


def err(errno: int, text: str | None = None) -> tuple:
    return ("error", errno, text)


OK = ("ok",)
APPROVAL, FORGED, SEALED, BETWEEN, DIRECT, SEPARATION, STATE, IDENTITY, CONTROL, TCB = (
    "publish without valid approval", "forged verification", "modify a sealed artifact",
    "change between verification and publication", "direct write to published tables", "separation of duties",
    "observation state", "identity preconditions", "positive control", "administrator (trusted computing base)")


@scenario("G01", APPROVAL, "Release a sealed batch that has no verification", err(1644, "has no verification"))
def _g01():
    batch, _ = sealed()
    return gate.release(batch)


@scenario("G02", APPROVAL, "Release a PASS batch without a human approval", err(1644, "no human approval"))
def _g02():
    batch, _, _ = verified("PASS")
    return gate.release(batch)


def _forge(account: str):
    batch, seal = sealed()
    return db.run(LAB, account, gate.verification_sql(batch, "PASS", seal["sealed_hash"], gate.observation_hash(),
                                                      CODE, ZERO, ZERO))


@scenario("G03", FORGED, "Builder records a PASS for its own batch", err(1142))
def _g03():
    return _forge(BR)


@scenario("G04", FORGED, "Approver records a PASS", err(1142))
def _g04():
    return _forge("m1_approver")


@scenario("G05", FORGED, "Agent records a PASS", err(1142))
def _g05():
    return _forge("m1_agent")


@scenario("G06", FORGED, "Release account records a PASS", err(1142))
def _g06():
    return _forge("m1_release")


@scenario("G07", FORGED, "Administrator records a PASS", err(1644, "only m1_verifier"))
def _g07():
    return _forge("root")


@scenario("G08", FORGED, "Verifier records a PASS with a hash that is not the sealed hash",
          err(1644, "does not match the seal"))
def _g08():
    batch, seal = sealed()
    return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", ZERO, gate.observation_hash(), CODE,
                                                            ZERO, ZERO))


@scenario("G09", FORGED, "Verifier records a PASS for a batch that is not sealed", err(1644, "not sealed"))
def _g09():
    batch = open_with_chunks()
    return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", ZERO, gate.observation_hash(), CODE,
                                                            ZERO, ZERO))


@scenario("G10", FORGED, "Verifier records a PASS for code that is not the batch's pipeline code",
          err(1644, "PASS requires"))
def _g10():
    batch, seal = sealed()
    return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", seal["sealed_hash"],
                                                            gate.observation_hash(), OTHER_CODE, ZERO, ZERO))


@scenario("G11", FORGED, "Verifier records a PASS against a stale observation state",
          err(1644, "observation state differs"))
def _g11():
    batch, seal = sealed()
    return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", seal["sealed_hash"], ZERO, CODE,
                                                            ZERO, ZERO))


@scenario("G12", SEALED, "Builder adds a chunk after the seal", err(1644, "batch is sealed"))
def _g12():
    batch, _ = sealed()
    return db.run(LAB, BR, gate.add_chunks_sql(batch, [(99, "gate-test:late", "Late chunk", _embedding(99))]))


@scenario("G13", SEALED, "Builder updates a sealed chunk", err(1142))
def _g13():
    batch, _ = sealed()
    return db.run(LAB, BR, f"UPDATE m1_kb_q.chunks SET content = 'x' WHERE batch_id = {batch};")


@scenario("G14", SEALED, "Administrator updates a sealed chunk", err(1644, "append-only"))
def _g14():
    batch, _ = sealed()
    return db.run(LAB, "root", f"UPDATE m1_kb_q.chunks SET content = 'x' WHERE batch_id = {batch};")


@scenario("G15", SEALED, "Administrator deletes a sealed chunk", err(1644, "append-only"))
def _g15():
    batch, _ = sealed()
    return db.run(LAB, "root", f"DELETE FROM m1_kb_q.chunks WHERE batch_id = {batch};")


@scenario("G16", SEALED, "Administrator rewrites a seal", err(1644, "seals are append-only"))
def _g16():
    batch, _ = sealed()
    return db.run(LAB, "root", f"UPDATE m1_ctl.seals SET sealed_hash = REPEAT('0', 64) WHERE batch_id = {batch};")


@scenario("G17", SEALED, "Administrator flips a FAIL verification to PASS", err(1644, "verifications are append-only"))
def _g17():
    batch, _, vid = verified("FAIL")
    return db.run(LAB, "root", f"UPDATE m1_ctl.verifications SET verdict = 'PASS' WHERE verification_id = {vid};")


@scenario("G18", SEALED, "Administrator edits sealed content behind the triggers, then the verifier records PASS",
          err(1644, "changed after the seal"))
def _g18():
    batch, seal = sealed()
    root_bypass_update(batch)
    return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", seal["sealed_hash"],
                                                            gate.observation_hash(), CODE, ZERO, ZERO))


@scenario("G19", APPROVAL, "Approve a FAIL verification", err(1644, "only a PASS"))
def _g19():
    batch, seal, vid = verified("FAIL")
    return db.run(LAB, "m1_approver", gate.approval_sql(vid, batch, "APPROVE", seal["sealed_hash"], "test"))


@scenario("G20", APPROVAL, "Approve an INCONCLUSIVE verification", err(1644, "only a PASS"))
def _g20():
    batch, seal, vid = verified("INCONCLUSIVE")
    return db.run(LAB, "m1_approver", gate.approval_sql(vid, batch, "APPROVE", seal["sealed_hash"], "test"))


@scenario("G21", APPROVAL, "Release a batch whose verification is FAIL (rejected by the approver)",
          err(1644, "latest verification is not PASS"))
def _g21():
    batch, seal, vid = verified("FAIL")
    gate.approve(vid, batch, "REJECT", seal["sealed_hash"], "rejected")
    return gate.release(batch)


@scenario("G22", APPROVAL, "Approve an older PASS after a newer FAIL", err(1644, "not the latest"))
def _g22():
    batch, seal, v1 = verified("PASS")
    gate.record_verification(batch, "FAIL", seal["sealed_hash"], gate.observation_hash(), CODE, ZERO, ZERO)
    return db.run(LAB, "m1_approver", gate.approval_sql(v1, batch, "APPROVE", seal["sealed_hash"], "test"))


@scenario("G23", APPROVAL, "Release after a FAIL is recorded on top of an approved PASS",
          err(1644, "latest verification is not PASS"))
def _g23():
    batch, seal, _, _ = approved()
    gate.record_verification(batch, "FAIL", seal["sealed_hash"], gate.observation_hash(), CODE, ZERO, ZERO)
    return gate.release(batch)


@scenario("G24", APPROVAL, "Release after the approver records REJECT on top of APPROVE",
          err(1644, "latest approval does not approve"))
def _g24():
    batch, seal, vid, _ = approved()
    gate.approve(vid, batch, "REJECT", seal["sealed_hash"], "changed my mind")
    return gate.release(batch)


@scenario("G25", APPROVAL, "Approve a hash other than the verified hash", err(1644, "approved hash differs"))
def _g25():
    batch, _, vid = verified("PASS")
    return db.run(LAB, "m1_approver", gate.approval_sql(vid, batch, "APPROVE", ZERO, "test"))


@scenario("G26", SEPARATION, "Verifier records the approval", err(1142))
def _g26():
    batch, seal, vid = verified("PASS")
    return db.run(LAB, "m1_verifier", gate.approval_sql(vid, batch, "APPROVE", seal["sealed_hash"], "test"))


@scenario("G27", SEPARATION, "Builder records the approval", err(1142))
def _g27():
    batch, seal, vid = verified("PASS")
    return db.run(LAB, BR, gate.approval_sql(vid, batch, "APPROVE", seal["sealed_hash"], "test"))


@scenario("G28", SEPARATION, "Builder calls the release procedure", err(1370))
def _g28():
    batch, _, _, _ = approved()
    return gate.release(batch, account=BR)


@scenario("G29", SEPARATION, "Agent calls the release procedure", err(1370))
def _g29():
    batch, _, _, _ = approved()
    return gate.release(batch, account="m1_agent")


@scenario("G30", SEPARATION, "Privileged builder adds a chunk to another builder's batch",
          err(1644, "only the batch builder may add"))
def _g30():
    batch = open_with_chunks(BR)
    return db.run(LAB, BP, gate.add_chunks_sql(batch, [(9, "gate-test:x", "Foreign chunk", _embedding(9))]))


@scenario("G31", SEPARATION, "Privileged builder seals another builder's batch", err(1644, "only the batch builder may seal"))
def _g31():
    batch = open_with_chunks(BR)
    return db.run(LAB, BP, gate.seal_sql(batch))


@scenario("G32", SEPARATION, "Verifier seals a batch", err(1142))
def _g32():
    batch = open_with_chunks(BR)
    return db.run(LAB, "m1_verifier", gate.seal_sql(batch))


@scenario("G33", SEPARATION, "Seal an empty batch", err(1644, "empty batch"))
def _g33():
    batch = gate.open_batch(BR, "gate-test", CODE)
    return db.run(LAB, BR, gate.seal_sql(batch))


@scenario("G34", SEPARATION, "Log in as the gate definer", err(3118))
def _g34():
    return db.run(LAB, "m1_gate_def", "SELECT 1;")


@scenario("G35", DIRECT, "Release account inserts into the published table directly", err(1142))
def _g35():
    return db.run(LAB, "m1_release", "INSERT INTO m1_kb_pub.chunks VALUES (1, 1, 'k', 'c', "
                  f"X'{_embedding(1).hex()}');")


@scenario("G36", DIRECT, "Agent inserts into the published table directly", err(1142))
def _g36():
    return db.run(LAB, "m1_agent", "INSERT INTO m1_kb_pub.chunks VALUES (1, 1, 'k', 'c', "
                  f"X'{_embedding(1).hex()}');")


@scenario("G37", DIRECT, "Administrator inserts a copy of an approved, sealed row into the published table",
          err(1644, "publication only through"))
def _g37():
    batch, _, _, _ = approved()
    return db.run(LAB, "root", "INSERT INTO m1_kb_pub.chunks SELECT * FROM m1_kb_q.chunks "
                  f"WHERE batch_id = {batch};")


@scenario("G38", DIRECT, "Administrator records a release row", err(1644, "recorded only by"))
def _g38():
    batch, seal, vid, aid = approved()
    return db.run(LAB, "root", "INSERT INTO m1_ctl.releases (batch_id, verification_id, approval_id, content_hash, "
                  f"obs_hash, row_count) VALUES ({batch}, {vid}, {aid}, '{seal['sealed_hash']}', "
                  f"'{seal['obs_hash']}', {seal['row_count']});")


CONTROL_BATCH: dict = {}


@scenario("G39", CONTROL, "Positive control: seal, PASS, APPROVE, release", OK)
def _g39():
    batch, seal, _, _ = approved()
    r = gate.release(batch)
    CONTROL_BATCH.update(batch=batch, seal=seal)
    return r


@scenario("G40", CONTROL, "Positive control: the published copy hashes to the sealed hash", ("value", True))
def _g40():
    return db.scalar(LAB, "root", f"SELECT m1_ctl.pub_hash({CONTROL_BATCH['batch']}) = "
                     f"'{CONTROL_BATCH['seal']['sealed_hash']}';") == "1"


@scenario("G41", DIRECT, "Release the same batch twice", err(1644, "already released"))
def _g41():
    return gate.release(CONTROL_BATCH["batch"])


@scenario("G42", DIRECT, "Administrator updates a published chunk", err(1644, "immutable"))
def _g42():
    return db.run(LAB, "root", f"UPDATE m1_kb_pub.chunks SET content = 'x' WHERE batch_id = {CONTROL_BATCH['batch']};")


@scenario("G43", DIRECT, "Administrator deletes a published chunk", err(1644, "immutable"))
def _g43():
    return db.run(LAB, "root", f"DELETE FROM m1_kb_pub.chunks WHERE batch_id = {CONTROL_BATCH['batch']};")


@scenario("G44", DIRECT, "Release account truncates the published table", err(1142))
def _g44():
    return db.run(LAB, "m1_release", "TRUNCATE TABLE m1_kb_pub.chunks;")


@scenario("G45", DIRECT, "Administrator deletes a release record", err(1644, "releases are append-only"))
def _g45():
    return db.run(LAB, "root", f"DELETE FROM m1_ctl.releases WHERE batch_id = {CONTROL_BATCH['batch']};")


@scenario("G46", BETWEEN, "Administrator edits approved content behind the triggers, then release",
          err(1644, "differs from the sealed"))
def _g46():
    batch, _, _, _ = approved()
    root_bypass_update(batch)
    return gate.release(batch)


def _changed_after_approval(change: str, undo: str):
    batch, _, _, _ = approved()
    db.must(LAB, "root", change, "change")
    try:
        return gate.release(batch)
    finally:
        db.must(LAB, "root", undo, "undo")


@scenario("G47", BETWEEN, "Unmasking role granted to the agent after approval, then release",
          err(1644, "observation state changed"))
def _g47():
    return _changed_after_approval("GRANT 'm1_r_unmask' TO 'm1_agent'@'%';",
                                   "REVOKE 'm1_r_unmask' FROM 'm1_agent'@'%';")


@scenario("G48", BETWEEN, "Masking policy created after approval, then release", err(1644, "observation state changed"))
def _g48():
    return _changed_after_approval(
        "CREATE MASKING POLICY m1_p_extra(v) CASE WHEN CURRENT_ROLE_IN('m1_r_unmask') THEN v ELSE '' END;",
        "DROP MASKING POLICY m1_p_extra;")


@scenario("G49", BETWEEN, "Global role activation switched on after approval, then release",
          err(1644, "observation state changed"))
def _g49():
    return _changed_after_approval("SET GLOBAL activate_all_roles_on_login = ON;",
                                   "SET GLOBAL activate_all_roles_on_login = OFF;")


@scenario("G50", TCB, "Known gap: column moved to another existing policy after approval, then release", OK)
def _g50():
    return _changed_after_approval(
        "ALTER TABLE m1_src.suppliers MODIFY compliance_note VARCHAR(300) NULL MASKING POLICY m1_p_tax;",
        "ALTER TABLE m1_src.suppliers MODIFY compliance_note VARCHAR(300) NULL MASKING POLICY m1_p_note;")


@scenario("G51", STATE, "Grant changed while a batch is being built, then seal",
          err(1644, "changed during the build"))
def _g51():
    batch = open_with_chunks(BR)
    db.must(LAB, "root", "GRANT SELECT ON m1_ops.* TO 'm1_agent'@'%';", "change")
    try:
        return db.run(LAB, BR, gate.seal_sql(batch))
    finally:
        db.must(LAB, "root", "REVOKE SELECT ON m1_ops.* FROM 'm1_agent'@'%';", "undo")


@scenario("G52", IDENTITY, "Anonymous account exists, then a builder opens a batch",
          err(1644, "identity preconditions failed"))
def _g52():
    # An address from TEST-NET-1: the account never matches a real connection.
    db.must(LAB, "root", "CREATE USER ''@'192.0.2.1' ACCOUNT LOCK;", "change")
    try:
        return db.run(LAB, BR, "INSERT INTO m1_kb_q.batches (pipeline, code_hash) VALUES ('gate-test', "
                      f"'{CODE}');")
    finally:
        db.must(LAB, "root", "DROP USER ''@'192.0.2.1';", "undo")


@scenario("G53", IDENTITY, "Proxy mapping exists, then the verifier records a verification",
          err(1644, "identity preconditions failed"))
def _g53():
    batch, seal = sealed()
    obs = gate.observation_hash()
    db.must(LAB, "root", "GRANT PROXY ON 'm1_world'@'%' TO 'm1_agent'@'%';", "change")
    try:
        return db.run(LAB, "m1_verifier", gate.verification_sql(batch, "PASS", seal["sealed_hash"], obs, CODE,
                                                                ZERO, ZERO))
    finally:
        db.must(LAB, "root", "REVOKE PROXY ON 'm1_world'@'%' FROM 'm1_agent'@'%';", "undo")


@scenario("G54", TCB, "Administrator truncates the published table; the integrity audit detects it", ("value", True))
def _g54():
    db.must(LAB, "root", "TRUNCATE TABLE m1_kb_pub.chunks;", "truncate")
    audit = gate.published_integrity()
    return bool(audit) and not any(a["intact"] for a in audit)


# --------------------------------------------------------------------------
# Runner
# --------------------------------------------------------------------------
def _judge(expect: tuple, outcome) -> tuple[bool, str]:
    if expect[0] == "value":
        return outcome == expect[1], f"value {outcome!r}"
    if isinstance(outcome, Exception):
        return False, f"setup failed: {outcome}"
    if expect[0] == "ok":
        return outcome.ok, "ok" if outcome.ok else f"ERROR {outcome.errno} {outcome.error}"
    _, errno, text = expect
    seen = "ok" if outcome.ok else f"ERROR {outcome.errno} {outcome.error}"
    passed = (not outcome.ok and outcome.errno == errno and (text is None or text in (outcome.error or "")))
    return passed, seen


def _observation_or_none() -> str | None:
    try:
        return gate.observation_hash()
    except db.SqlError:
        return None


def run_all() -> dict:
    cfg = config.load()
    baseline = _observation_or_none()
    results = []
    for s in SCENARIOS:
        try:
            outcome = s.fn()
        except Exception as exc:  # a preparation step failed: the scenario fails, the run goes on
            outcome = exc
        passed, seen = _judge(s.expect, outcome)
        results.append(dict(id=s.sid, category=s.category, title=s.title,
                            expected=" ".join(str(x) for x in s.expect if x is not None), observed=seen,
                            result="PASS" if passed else "FAIL"))
        print(f"{s.sid} {'PASS' if passed else 'FAIL'}  {s.title}\n      expected {results[-1]['expected']}"
              f" | observed {seen}")
    restored = baseline is not None and _observation_or_none() == baseline
    report = dict(kind="gate-negatives", at=dt.datetime.now().isoformat(timespec="seconds"),
                  passed=sum(r["result"] == "PASS" for r in results), total=len(results),
                  observation_state_restored=restored, scenarios=results)
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.results_dir / f"negatives-{dt.datetime.now():%Y%m%d-%H%M%S}.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"{report['passed']}/{report['total']} as expected; observation state restored: {restored}; raw: {path.name}")
    return report
