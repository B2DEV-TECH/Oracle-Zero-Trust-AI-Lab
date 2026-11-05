"""Downloads the pinned BAAI/bge-small-en-v1.5 files once and writes a SHA-256 manifest.

Pinned to one Hugging Face commit. The ONNX weights are checked against the
LFS SHA-256 the hub publishes for that commit; the small JSON/tokenizer files
are recorded in the manifest so later runs can detect any change.
Usage: venv\\Scripts\\python.exe -I fetch_model.py <dest-dir>
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

from huggingface_hub import hf_hub_download

REPO = "BAAI/bge-small-en-v1.5"
REVISION = "5c38ec7c405ec4b44b94cc5a9bb96e735b38267a"
FILES = ["onnx/model.onnx", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json",
         "config.json", "1_Pooling/config.json"]
LFS_SHA256 = {"onnx/model.onnx": "828e1496d7fabb79cfa4dcd84fa38625c0d3d21da474a00f08db0f559940cf35"}


def main(dest: Path) -> int:
    lines = [f"# {REPO} @ {REVISION}"]
    for name in FILES:
        path = Path(hf_hub_download(REPO, name, revision=REVISION, local_dir=dest))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = LFS_SHA256.get(name)
        if expected and digest != expected:
            print(f"MODEL_ABORT: {name} sha256 {digest} != hub {expected}")
            return 1
        print(f"{'MATCH' if expected else 'RECORD':6} {name} {digest}")
        lines.append(f"{digest}  {name}")
    (dest / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="ascii")
    print("MODEL_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))
