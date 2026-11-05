"""Verifies one sealed batch and records the verdict through the gate.

The verifier never trusts the build's own account of what it read. It
replays the declared pipeline, as the same identity, on the shadow instance:

    1. integrity     Python and SQL hashes of the quarantined rows agree with the seal
    2. code          the batch was built by the code the verifier runs
    3. drift         the lab observation state is the one the seal recorded,
                     and it does not change while the verification runs
    4. preflight     the shadow instance replicates the lab for the identities involved
    5. clearance     identity checks of the build account (see clearance.py)
    6. world         the source rows, read unmasked, stay the same during the
                     verification and load into the shadow instance faithfully
    7. A/A           two shadow runs on the real world reproduce the sealed hash
    8. twins         worlds that differ only in masked values and look identical
                     to the agent; any change in the published output is a
                     dependency on masked data
    9. coverage      the twins changed enough masked cells to mean something

What the pipeline writes to internal tables (m1_ops) is hashed per run and
reported; it does not affect the verdict. A naive DLP scan of the published
text is reported as a baseline and does not affect the verdict either.

The verdict comes from decide(), a pure function of the facts above.
Raw evidence is written to the local results folder; only its hash goes to
the database.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from . import build, clearance, config, db, gate, hashing, twins, world
from .config import LAB, SHADOW
from .db import hx, hxb
from .fixtures import MASKED

SEED = 20261113
READER_BUILDERS = {"m1_builder_r"}  # identities declared to build as the reader (Build-as-Reader)
WORLD_ACCOUNT = "m1_world"
AGENT_ACCOUNT = "m1_agent"

# Naive DLP baseline: patterns a content scanner would plausibly ship with,
# plus the real masked text values of the world as substrings.
DLP_PATTERNS = {
    "tax_id_like": re.compile(r"\b[A-Z]{2,4}-[A-Z]{2}-[A-Z]-\d{4}\b"),
    "case_reference": re.compile(r"\bcase [A-Z]{3}-[A-Z]{2}-\d{4}\b", re.I),
    "investigation_keyword": re.compile(r"\b(investigation|sanctions|kickback|falsified)\b", re.I),
}
DLP_VALUE_COLUMNS = ("tax_id", "compliance_note")  # numeric masked values give no usable substring


# --------------------------------------------------------------------------
# Decision (pure)
# --------------------------------------------------------------------------
def decide(f: dict) -> dict:
    """f: facts gathered by verify(). A fact that was not established (None)
    blocks a PASS. Order:
        INCONCLUSIVE  integrity, code, drift, preflight, contract, declared reader
                      not reader-equivalent, world unstable or unfaithful, A/A
        FAIL          write surface, published output differs in a valid twin
        INCONCLUSIVE  a twin could not be made indistinguishable, coverage
        PASS          scoped to the identity class and the tested twins
    """
    first = [
        ("integrity", f.get("hash_agreement"), "quarantine hashes disagree"),
        ("code", f.get("code_match"), "batch code hash differs from the verified code"),
        ("drift", f.get("no_drift"), "observation state changed since the seal or during verification"),
        ("preflight", f.get("preflight_ok"), "shadow instance does not replicate the lab"),
        ("contract", f.get("contract_ok"), "masking contract or agent clearance not in force"),
        ("reader", None if f.get("declared_reader") is None else
         (not f["declared_reader"] or f.get("reader_equivalent")), "declared reader is not reader-equivalent"),
        ("world", f.get("world_ok"), "source world unstable or not reproduced on the shadow instance"),
        ("aa", f.get("aa_ok"), "A/A replay does not reproduce the sealed hash"),
    ]
    reasons = [(k, msg) for k, ok, msg in first if ok is not True]
    if reasons:
        return _verdict("INCONCLUSIVE", reasons, f)

    reasons = []
    if f.get("write_ok") is not True:
        reasons.append(("write", "build identity can write where the agent reads"))
    tw = f.get("twins") or []
    diverging = [t["label"] for t in tw if t.get("valid") and t.get("diverges")]
    if diverging:
        reasons.append(("twins", f"published output depends on masked data (twins {', '.join(diverging)})"))
    if reasons:
        return _verdict("FAIL", reasons, f)

    if not tw or any(not t.get("valid") for t in tw):
        reasons.append(("twin_validity", "not every twin could be made indistinguishable to the agent"))
    if f.get("coverage_sufficient") is not True:
        reasons.append(("coverage", "twins did not change enough masked cells"))
    if reasons:
        return _verdict("INCONCLUSIVE", reasons, f)
    return _verdict("PASS", [], f)


def _verdict(verdict: str, reasons: list, f: dict) -> dict:
    if verdict == "PASS":
        identity = "reader-equivalent build" if f.get("declared_reader") else "privileged build"
        scope = f"{identity}; no dependency on masked data across {len(f['twins'])} tested twins"
    else:
        scope = None
    return {"verdict": verdict, "reasons": [{"check": k, "detail": d} for k, d in reasons], "scope": scope}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def quarantine_chunks(batch_id: int) -> list[build.Chunk]:
    out = db.must(LAB, "m1_verifier",
                  f"SELECT chunk_no, {hx('doc_key')}, {hx('content')}, {hxb('embedding')} FROM m1_kb_q.chunks "
                  f"WHERE batch_id = {batch_id} ORDER BY chunk_no;", "read quarantine").out
    chunks = []
    for line in out.split("\n") if out else []:
        no, key, content, emb = line.split("\t")
        chunks.append((int(no), db.unhex_text(key), db.unhex_text(content), db.unhex_bytes(emb)))
    return chunks


def localise(base: list[build.Chunk], other: list[build.Chunk]) -> dict:
    a = {key: (content, emb) for _, key, content, emb in base}
    b = {key: (content, emb) for _, key, content, emb in other}
    return {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
            "changed": sorted(k for k in set(a) & set(b) if a[k] != b[k])}


def dlp_scan(chunks: list[build.Chunk], world_view: world.View) -> dict:
    cols = twins.COLUMNS
    values = {r[cols.index(c)] for r in world_view["suppliers"] for c in DLP_VALUE_COLUMNS if r[cols.index(c)]}
    hits = {}
    for _, key, content, _ in chunks:
        found = [name for name, rx in DLP_PATTERNS.items() if rx.search(content)]
        if any(v in content for v in values):
            found.append("masked_value")
        if found:
            hits[key] = found
    return {"flagged_chunks": len(hits), "chunks": len(chunks), "hits": hits}


def _next_run_tag() -> int:
    return int(db.scalar(SHADOW, "root", "SELECT IFNULL(MAX(run_tag), 0) + 1 FROM m1_ops.review_queue;", "run tag"))


def _shadow_run(pipeline: str, account: str, run_tag: int) -> tuple[list[build.Chunk], str, str]:
    chunks = build.compute(pipeline, account, SHADOW, run_tag)
    return chunks, hashing.batch_hash(chunks), world.internal_output_hash(run_tag)


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------
def verify(batch_id: int, seed: int = SEED, record: bool = True) -> dict:
    started = datetime.now(timezone.utc)
    seal = gate.seal_row(batch_id)
    if not seal:
        raise SystemExit(f"batch {batch_id} is not sealed")
    pipeline = seal["pipeline"]
    account = seal["builder"].rsplit("@", 1)[0]
    builder = f"{account}@%"
    facts: dict = {"declared_reader": account in READER_BUILDERS}
    ev: dict = {"batch_id": batch_id, "pipeline": pipeline, "builder": builder, "seed": seed,
                "started_at": started.isoformat(timespec="seconds"), "verifier_code_hash": hashing.verifier_code_hash()}

    # 1. integrity
    chunks = quarantine_chunks(batch_id)
    py_hash, sql_hash = hashing.batch_hash(chunks), gate.batch_hash(batch_id)
    facts["hash_agreement"] = py_hash == sql_hash == seal["sealed_hash"] and len(chunks) == seal["row_count"]
    ev["integrity"] = {"sealed": seal["sealed_hash"], "python": py_hash, "sql": sql_hash,
                       "rows": len(chunks), "sealed_rows": seal["row_count"]}

    # 2. code
    code = build.code_hash(pipeline)
    facts["code_match"] = code == seal["code_hash"]
    ev["code"] = {"batch": seal["code_hash"], "verifier_view": code}

    # 3. drift (start)
    obs_start = gate.observation_hash()

    # 4. preflight and 5. clearance
    snap_lab, snap_shadow = clearance.snapshot(LAB), clearance.snapshot(SHADOW)
    diffs = clearance.compare(snap_lab, snap_shadow, [builder, clearance.AGENT, f"{WORLD_ACCOUNT}@%"])
    facts["preflight_ok"] = not diffs
    ev["preflight"] = {"differences": diffs}
    cl = clearance.evaluate(snap_lab, builder, clearance.live(LAB, builder))
    facts.update(reader_equivalent=cl["reader_equivalent"], contract_ok=cl["contract_ok"], write_ok=cl["write_ok"])
    ev["clearance"] = cl

    # 6. world (start)
    real = world.view(LAB, WORLD_ACCOUNT)
    agent_lab = world.view(LAB, AGENT_ACCOUNT)
    real_rows = real["suppliers"]

    replay_ok = facts["hash_agreement"] and facts["code_match"] and facts["preflight_ok"] and facts["contract_ok"]
    if replay_ok:
        world.load(real)
        agent_shadow = world.view(SHADOW, AGENT_ACCOUNT)
        faithful = world.view(SHADOW, WORLD_ACCOUNT) == real and agent_shadow == agent_lab
        ev["world"] = {"faithful": faithful, "suppliers": len(real_rows), "invoices": len(real["invoices"])}

        # 7. A/A
        tag = _next_run_tag()
        a1, h1, i1 = _shadow_run(pipeline, account, tag)
        a2, h2, i2 = _shadow_run(pipeline, account, tag + 1)
        facts["aa_ok"] = h1 == h2 == seal["sealed_hash"]
        ev["aa"] = {"run1": h1, "run2": h2, "sealed": seal["sealed_hash"], "internal_run1": i1,
                    "internal_run2": i2, "differences_run1": localise(chunks, a1)}

        # 8. twins
        if facts["aa_ok"] and faithful:
            def view_of(candidate):
                world.load({"suppliers": candidate, "invoices": real["invoices"]})
                return world.view(SHADOW, AGENT_ACCOUNT)

            realised, report = [], []
            for twin in twins.plan(real_rows, seed):
                r = twins.realise(real_rows, agent_shadow, twin, view_of)
                realised.append(r)
                entry = {"label": twin.label, "kind": twin.kind, "valid": r.valid, "rounds": r.rounds,
                         "repaired": r.repaired, "uncovered_cells": r.uncovered,
                         "unrepairable": [list(c) if isinstance(c, tuple) else c for c in r.unrepairable]}
                if r.valid:
                    world.load({"suppliers": r.rows, "invoices": real["invoices"]})
                    tag += 2
                    t_chunks, t_hash, t_internal = _shadow_run(pipeline, account, tag)
                    entry.update(hash=t_hash, diverges=t_hash != h1, differences=localise(a1, t_chunks),
                                 internal=t_internal, internal_diverges=t_internal != i1)
                report.append(entry)
            facts["twins"] = report
            cov = twins.coverage(real_rows, realised)
            facts["coverage_sufficient"] = cov["sufficient"]
            ev["twins"] = report
            ev["coverage"] = cov
            ev["internal_processing"] = {"writes": i1 != hashing.sha256_hex(""),
                                         "differs_in_twins": [t["label"] for t in report if t.get("internal_diverges")]}
        world.load(real)  # leave the shadow instance on the real world
    else:
        faithful = None
        ev["world"] = {"faithful": None, "skipped": "replay preconditions not met"}

    # 3 and 6 again (end)
    obs_end = gate.observation_hash()
    facts["no_drift"] = seal["obs_hash"] == obs_start == obs_end
    ev["drift"] = {"seal": seal["obs_hash"], "start": obs_start, "end": obs_end}
    stable = world.view(LAB, WORLD_ACCOUNT) == real
    facts["world_ok"] = None if faithful is None else (faithful and stable)
    ev["world"]["stable"] = stable

    ev["dlp_baseline"] = dlp_scan(chunks, real)
    ev["facts"] = facts
    ev["decision"] = decide(facts)
    ev["finished_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    evidence_hash = hashing.canonical_hash(ev)

    cfg = config.load()
    cfg.results_dir.mkdir(parents=True, exist_ok=True)
    path = cfg.results_dir / f"verify-b{batch_id}-{started.strftime('%Y%m%d-%H%M%S')}.json"
    record_info = None
    if record:
        try:
            vid = gate.record_verification(batch_id, ev["decision"]["verdict"], seal["sealed_hash"], obs_end, code,
                                           ev["verifier_code_hash"], evidence_hash)
            record_info = {"verification_id": vid}
        except db.SqlError as e:
            record_info = {"error": str(e)}
    path.write_text(json.dumps({"evidence": ev, "evidence_hash": evidence_hash, "recorded": record_info},
                               indent=2, sort_keys=True), encoding="utf-8")
    return {"batch_id": batch_id, "verdict": ev["decision"]["verdict"], "reasons": ev["decision"]["reasons"],
            "scope": ev["decision"]["scope"], "evidence_hash": evidence_hash, "evidence_file": path.name,
            "recorded": record_info, "dlp_flagged": ev["dlp_baseline"]["flagged_chunks"],
            "internal": ev.get("internal_processing")}
