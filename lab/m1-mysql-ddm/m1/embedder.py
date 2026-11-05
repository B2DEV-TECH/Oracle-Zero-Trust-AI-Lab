"""Local, offline, single-threaded embedder: BAAI/bge-small-en-v1.5 through
fastembed, from a model folder whose files are pinned by MANIFEST.sha256.

Before the model loads, every file in the manifest is checked, Hugging Face
Hub is switched to offline mode and Python sockets are disabled, so a missing
or altered file fails instead of being fetched. Database access is not
affected: it goes through the mysql client in a separate process.
"""

from __future__ import annotations

import hashlib
import os
import socket
from importlib.metadata import version
from pathlib import Path

MODEL_ID = "BAAI/bge-small-en-v1.5"
MODEL_NAME = "m1/bge-small-en-v1.5-baai-onnx"
DIM = 384
PACKAGES = ["fastembed", "onnxruntime", "tokenizers", "numpy", "huggingface-hub"]

_model = None


class NetworkBlocked(RuntimeError):
    pass


def block_network() -> None:
    class _Blocked(socket.socket):
        def __init__(self, *args, **kwargs):
            raise NetworkBlocked("network access attempted while embedding")

    def _refuse(*args, **kwargs):
        raise NetworkBlocked("network access attempted while embedding")

    os.environ["HF_HUB_OFFLINE"] = "1"
    socket.socket = _Blocked
    socket.create_connection = _refuse


def read_manifest(model_dir: Path) -> tuple[str, dict[str, str]]:
    revision, files = "", {}
    for line in (model_dir / "MANIFEST.sha256").read_text(encoding="ascii").splitlines():
        if line.startswith("#"):
            revision = line.split("@", 1)[1].strip()
        elif line.strip():
            digest, name = line.split(None, 1)
            files[name.strip()] = digest
    return revision, files


def verify_manifest(model_dir: Path) -> dict:
    revision, files = read_manifest(model_dir)
    if not revision or "onnx/model.onnx" not in files:
        raise RuntimeError("model manifest is incomplete")
    for name, digest in files.items():
        if hashlib.sha256((model_dir / name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f"model file does not match the manifest: {name}")
    return {"model": MODEL_ID, "revision": revision, "files": files}


def identity(model_dir: Path) -> dict:
    """What decides the embedding bytes: pinned files, runtime versions, settings."""
    revision, files = read_manifest(model_dir)
    return {"model": MODEL_ID, "revision": revision, "files": files,
            "packages": {p: version(p) for p in PACKAGES},
            "settings": {"pooling": "CLS", "normalization": True, "threads": 1, "batch_size": 1}}


def load(model_dir: Path):
    global _model
    if _model is None:
        verify_manifest(model_dir)
        block_network()
        from fastembed import TextEmbedding
        from fastembed.common.model_description import ModelSource, PoolingType
        TextEmbedding.add_custom_model(model=MODEL_NAME, pooling=PoolingType.CLS, normalization=True,
                                       sources=ModelSource(hf=MODEL_ID), dim=DIM,
                                       model_file="onnx/model.onnx", license="mit")
        _model = TextEmbedding(model_name=MODEL_NAME, specific_model_path=str(model_dir), threads=1)
    return _model


def embed(model_dir: Path, texts: list[str]) -> list[bytes]:
    """One float32 little-endian vector per text: the byte layout of MySQL VECTOR."""
    model = load(model_dir)
    return [v.astype("<f4").tobytes() for v in model.embed(texts, batch_size=1, parallel=None)]
