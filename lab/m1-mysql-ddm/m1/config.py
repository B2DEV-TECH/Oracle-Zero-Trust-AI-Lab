"""Local configuration. Nothing here is committed: paths, ports and passwords
live outside the repository.

The JSON file named by the M1_CONFIG environment variable holds:
    mysql_client  path to the MySQL Enterprise `mysql` command-line client
    secrets_dir   folder with one client option file per instance and account,
                  named <instance>-<account>.cnf (the administrator's is
                  <instance>-root.cnf and must exist before setup)
    results_dir   folder for raw, unsanitized results (kept local)
    model_dir     folder with the pinned embedding model and its MANIFEST.sha256
See config.template.json.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

LAB = "lab"        # the instance the pipelines, the gate and the agent use
SHADOW = "shadow"  # the verifier's private instance for replays and twins
INSTANCES = (LAB, SHADOW)


@dataclass(frozen=True)
class Config:
    mysql_client: Path
    secrets_dir: Path
    results_dir: Path
    model_dir: Path

    def cnf(self, instance: str, account: str) -> Path:
        return self.secrets_dir / f"{instance}-{account}.cnf"


_cached: Config | None = None


def load() -> Config:
    global _cached
    if _cached is None:
        name = os.environ.get("M1_CONFIG")
        if not name:
            raise SystemExit("M1_CONFIG is not set; point it to a local copy of config.template.json")
        raw = json.loads(Path(name).read_text(encoding="utf-8"))
        _cached = Config(*(Path(raw[k]) for k in ("mysql_client", "secrets_dir", "results_dir", "model_dir")))
    return _cached
