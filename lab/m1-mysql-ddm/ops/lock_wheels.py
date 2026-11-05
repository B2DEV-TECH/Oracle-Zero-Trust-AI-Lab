"""Builds requirements.lock for the M1 embedder venv from a downloaded wheelhouse.

Every wheel's SHA-256 is computed locally and compared with the digest PyPI
publishes for that exact file (JSON API). The lock is written only when every
file matches. Usage: py -3.13 -I lock_wheels.py <wheelhouse> <out-lock>
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)-")


def pypi_digests(name: str, version: str) -> dict[str, str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=60) as resp:
        data = json.load(resp)
    return {f["filename"]: f["digests"]["sha256"] for f in data["urls"]}


def main(wheelhouse: Path, out: Path) -> int:
    lines, bad = [], 0
    for whl in sorted(wheelhouse.glob("*.whl")):
        m = WHEEL_RE.match(whl.name)
        name, ver = m.group("name"), m.group("ver")
        local = hashlib.sha256(whl.read_bytes()).hexdigest()
        remote = pypi_digests(name, ver).get(whl.name)
        status = "MATCH" if remote == local else f"MISMATCH (pypi={remote})"
        print(f"{status:8} {whl.name} {local}")
        if remote != local:
            bad += 1
        lines.append(f"{name.replace('_', '-').lower()}=={ver} --hash=sha256:{local}")
    if bad:
        print(f"LOCK_ABORT: {bad} file(s) do not match PyPI")
        return 1
    out.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"LOCK_OK {len(lines)} wheels -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), Path(sys.argv[2])))
