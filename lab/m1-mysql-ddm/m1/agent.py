"""The agent: semantic search over the published knowledge base.

It runs as m1_agent, reads only what the gate released into m1_kb_pub,
embeds the question with the same pinned embedder and ranks chunks by cosine
similarity in Python. There is no language model: the answer is the ranked
chunks, so what the agent can return is exactly what was released.
"""

from __future__ import annotations

import struct

from . import config, db, embedder
from .config import LAB
from .db import hx, hxb

AGENT = "m1_agent"
# Retrieval instruction recommended for bge-small-en-v1.5 queries (not for passages).
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "


def _vector(emb: bytes) -> tuple[float, ...]:
    return struct.unpack(f"<{len(emb) // 4}f", emb)


def rank(query: bytes, chunks: list[tuple[int, str, str, bytes]], k: int) -> list[dict]:
    """Top k chunks by cosine similarity. Vectors are normalised by the
    embedder, so the dot product is the cosine. Ties keep chunk order."""
    q = _vector(query)
    scored = [(sum(a * b for a, b in zip(q, _vector(emb))), no, key, content) for no, key, content, emb in chunks]
    scored.sort(key=lambda s: (-s[0], s[1]))
    return [{"doc_key": key, "score": round(score, 4), "content": content} for score, _, key, content in scored[:k]]


def released_batch(instance: str = LAB) -> int | None:
    value = db.scalar(instance, AGENT, "SELECT IFNULL(MAX(batch_id), 'NULL') FROM m1_kb_pub.chunks;", "latest batch")
    return None if value == "NULL" else int(value)


def published_chunks(batch_id: int, instance: str = LAB) -> list[tuple[int, str, str, bytes]]:
    out = db.must(instance, AGENT,
                  f"SELECT chunk_no, {hx('doc_key')}, {hx('content')}, {hxb('embedding')} FROM m1_kb_pub.chunks "
                  f"WHERE batch_id = {int(batch_id)} ORDER BY chunk_no;", "read published chunks").out
    chunks = []
    for line in out.split("\n") if out else []:
        no, key, content, emb = line.split("\t")
        chunks.append((int(no), db.unhex_text(key), db.unhex_text(content), db.unhex_bytes(emb)))
    return chunks


def search(question: str, k: int = 5, batch_id: int | None = None, instance: str = LAB) -> dict:
    batch = batch_id if batch_id is not None else released_batch(instance)
    if batch is None:
        return {"batch_id": None, "question": question, "results": [], "note": "nothing has been released"}
    query = embedder.embed(config.load().model_dir, [QUERY_PREFIX + question])[0]
    return {"batch_id": batch, "question": question, "results": rank(query, published_chunks(batch, instance), k)}
