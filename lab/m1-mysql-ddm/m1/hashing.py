"""Hashes shared by the build, the verifier and the evidence.

batch_hash() is the Python twin of m1_ctl.batch_hash() in 20_gate.sql:

    h = sha256('m1-batch-v1')
    for each chunk in chunk_no order:
        row = sha256(chunk_no | doc_key | HEX(content utf8) | HEX(embedding float32 LE))
        h = sha256(h || row)

All digests are lowercase hex, exactly as MySQL's SHA2() returns them. The
two implementations are compared against each other on every verification.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

BATCH_DOMAIN = "m1-batch-v1"
PACKAGE_DIR = Path(__file__).resolve().parent

# Everything that decides what a pipeline publishes. The verifier refuses to
# vouch for a batch whose declared code hash differs from the code it runs.
PIPELINE_SOURCES = ["config.py", "db.py", "hashing.py", "embedder.py", "pipelines.py", "build.py"]
VERIFIER_SOURCES = PIPELINE_SOURCES + ["fixtures.py", "world.py", "twins.py", "clearance.py", "verifier.py"]


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


def row_hash(chunk_no: int, doc_key: str, content: str, embedding: bytes) -> str:
    return sha256_hex(f"{chunk_no}|{doc_key}|{content.encode('utf-8').hex().upper()}|{embedding.hex().upper()}")


def batch_hash(chunks) -> str:
    """chunks: iterable of (chunk_no, doc_key, content, embedding bytes)."""
    h = sha256_hex(BATCH_DOMAIN)
    for no, key, content, emb in sorted(chunks, key=lambda c: c[0]):
        h = sha256_hex(h + row_hash(no, key, content, emb))
    return h


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_hash(obj) -> str:
    return sha256_hex(canonical(obj))


def source_digest(name: str) -> str:
    """Digest of one package source, with line endings normalised so that a
    checkout with CRLF and one with LF hash the same."""
    return sha256_hex((PACKAGE_DIR / name).read_bytes().replace(b"\r\n", b"\n"))


def code_hash(pipeline: str, embedder_identity: dict) -> str:
    return canonical_hash({
        "domain": "m1-code-v1",
        "pipeline": pipeline,
        "sources": {name: source_digest(name) for name in PIPELINE_SOURCES},
        "embedder": embedder_identity,
    })


def verifier_code_hash() -> str:
    return canonical_hash({"domain": "m1-verifier-v1",
                           "sources": {name: source_digest(name) for name in VERIFIER_SOURCES}})
