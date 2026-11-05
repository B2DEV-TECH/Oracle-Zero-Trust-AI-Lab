"""Client side of the publication gate. Each step runs as its own account;
the server-side triggers and the release procedure decide what is accepted.
"""

from __future__ import annotations

from . import db
from .config import LAB
from .db import q

BUILDERS = ("m1_builder_p", "m1_builder_r")


def open_batch(builder: str, pipeline: str, code_hash: str, instance: str = LAB) -> int:
    out = db.must(instance, builder,
                  f"INSERT INTO m1_kb_q.batches (pipeline, code_hash) VALUES ({q(pipeline)}, {q(code_hash)});\n"
                  "SELECT LAST_INSERT_ID();", "open batch").out
    return int(out.split("\n")[-1])


def chunk_values(batch_id: int, chunks: list[tuple[int, str, str, bytes]]) -> str:
    return ",\n  ".join(f"({batch_id}, {no}, {q(key)}, {q(content)}, X'{emb.hex()}')"
                        for no, key, content, emb in chunks)


def add_chunks_sql(batch_id: int, chunks: list[tuple[int, str, str, bytes]]) -> str:
    return ("INSERT INTO m1_kb_q.chunks (batch_id, chunk_no, doc_key, content, embedding) VALUES\n  "
            + chunk_values(batch_id, chunks) + ";")


def add_chunks(builder: str, batch_id: int, chunks, instance: str = LAB) -> None:
    db.must(instance, builder, add_chunks_sql(batch_id, chunks), "add chunks")


def seal_sql(batch_id: int) -> str:
    return f"INSERT INTO m1_ctl.seals (batch_id) VALUES ({batch_id});"


def seal(builder: str, batch_id: int, instance: str = LAB) -> dict:
    db.must(instance, builder, seal_sql(batch_id), "seal")
    return seal_row(batch_id, instance)


def seal_row(batch_id: int, instance: str = LAB) -> dict:
    out = db.must(instance, "m1_verifier",
                  "SELECT s.sealed_hash, s.row_count, s.obs_hash, b.code_hash, b.pipeline, b.builder "
                  f"FROM m1_ctl.seals s JOIN m1_kb_q.batches b USING (batch_id) WHERE s.batch_id = {batch_id};",
                  "read seal").out
    if not out:
        return {}
    sealed_hash, rows, obs, code, pipeline, builder = out.split("\t")
    return dict(batch_id=batch_id, sealed_hash=sealed_hash, row_count=int(rows), obs_hash=obs,
                code_hash=code, pipeline=pipeline, builder=builder)


def verification_sql(batch_id: int, verdict: str, content_hash: str, obs_hash: str, pipeline_code_hash: str,
                     verifier_code_hash: str, evidence_hash: str) -> str:
    return ("INSERT INTO m1_ctl.verifications (batch_id, verdict, content_hash, obs_hash, pipeline_code_hash, "
            "verifier_code_hash, evidence_hash) VALUES "
            f"({batch_id}, {q(verdict)}, {q(content_hash)}, {q(obs_hash)}, {q(pipeline_code_hash)}, "
            f"{q(verifier_code_hash)}, {q(evidence_hash)});\nSELECT LAST_INSERT_ID();")


def record_verification(batch_id: int, verdict: str, content_hash: str, obs_hash: str, pipeline_code_hash: str,
                        verifier_code_hash: str, evidence_hash: str, account: str = "m1_verifier",
                        instance: str = LAB) -> int:
    out = db.must(instance, account, verification_sql(batch_id, verdict, content_hash, obs_hash, pipeline_code_hash,
                                                      verifier_code_hash, evidence_hash), "record verification").out
    return int(out.split("\n")[-1])


def approval_sql(verification_id: int, batch_id: int, decision: str, content_hash: str, note: str) -> str:
    return ("INSERT INTO m1_ctl.approvals (verification_id, batch_id, decision, content_hash, note) VALUES "
            f"({verification_id}, {batch_id}, {q(decision)}, {q(content_hash)}, {q(note)});\nSELECT LAST_INSERT_ID();")


def approve(verification_id: int, batch_id: int, decision: str, content_hash: str, note: str,
            account: str = "m1_approver", instance: str = LAB) -> int:
    out = db.must(instance, account, approval_sql(verification_id, batch_id, decision, content_hash, note),
                  "record approval").out
    return int(out.split("\n")[-1])


def release_sql(batch_id: int) -> str:
    return f"CALL m1_ctl.release_batch({batch_id});"


def release(batch_id: int, account: str = "m1_release", instance: str = LAB) -> db.Result:
    return db.run(instance, account, release_sql(batch_id))


def observation_hash(instance: str = LAB) -> str:
    return db.scalar(instance, "m1_verifier", "SELECT m1_ctl.observation_state_hash();", "observation hash")


def batch_hash(batch_id: int, instance: str = LAB) -> str:
    return db.scalar(instance, "m1_verifier", f"SELECT m1_ctl.batch_hash({batch_id});", "batch hash")


def latest_verification(batch_id: int, instance: str = LAB) -> dict:
    out = db.must(instance, "m1_approver",
                  "SELECT verification_id, verdict, content_hash, verified_by, evidence_hash FROM m1_ctl.verifications "
                  f"WHERE batch_id = {batch_id} ORDER BY verification_id DESC LIMIT 1;", "latest verification").out
    if not out:
        return {}
    vid, verdict, content_hash, verified_by, evidence_hash = out.split("\t")
    return dict(verification_id=int(vid), verdict=verdict, content_hash=content_hash, verified_by=verified_by,
                evidence_hash=evidence_hash)


def published_integrity(instance: str = LAB) -> list[dict]:
    """Audit: every released batch must still hash to its released content hash."""
    out = db.must(instance, "m1_verifier",
                  "SELECT r.batch_id, r.content_hash, r.row_count, "
                  "(SELECT COUNT(*) FROM m1_kb_pub.chunks c WHERE c.batch_id = r.batch_id) "
                  "FROM m1_ctl.releases r ORDER BY r.batch_id;", "published integrity").out
    report = []
    for line in out.split("\n") if out else []:
        batch_id, content_hash, rows, now_rows = line.split("\t")
        now = db.scalar(instance, "m1_verifier", f"SELECT m1_ctl.pub_hash({batch_id});", "pub hash")
        report.append(dict(batch_id=int(batch_id), intact=(now == content_hash and rows == now_rows),
                           released_rows=int(rows), current_rows=int(now_rows)))
    return report
