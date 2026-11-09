"""Runs a pipeline. compute() is the whole build without side effects on the
gate: read the source as the build identity, render documents, embed them.
The lab build wraps it in the quarantine flow (open, add chunks, seal); the
verifier calls the same compute() on the shadow instance.
"""

from __future__ import annotations

from . import config, embedder, gate, hashing
from .config import LAB
from .pipelines import PIPELINES

Chunk = tuple[int, str, str, bytes]  # chunk_no, doc_key, content, embedding (float32 LE)


def code_hash(pipeline: str) -> str:
    return hashing.code_hash(pipeline, embedder.identity(config.load().model_dir))


def compute(pipeline: str, account: str, instance: str, run_tag: int) -> list[Chunk]:
    docs = PIPELINES[pipeline](instance, account, run_tag)
    vectors = embedder.embed(config.load().model_dir, [text for _, text in docs])
    return [(no, key, text, vec) for no, ((key, text), vec) in enumerate(zip(docs, vectors), start=1)]


def build_lab(pipeline: str, account: str) -> dict:
    """Builds one batch in the lab quarantine and seals it. The batch id is
    also the run tag of any internal output the pipeline writes."""
    batch_id = gate.open_batch(account, pipeline, code_hash(pipeline))
    chunks = compute(pipeline, account, LAB, run_tag=batch_id)
    gate.add_chunks(account, batch_id, chunks)
    seal = gate.seal(account, batch_id)
    seal["python_hash"] = hashing.batch_hash(chunks)
    return seal
