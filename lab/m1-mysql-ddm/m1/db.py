"""MySQL access through the official `mysql` client, one session per call.

Each call authenticates as a real account from its option file, so every
privilege decision is made by the server. Nothing is mocked. Passwords never
appear on the command line: the client reads them from the option file.

Values that may contain tabs, newlines or binary data are selected through
hx() / hxb() and decoded here, so the batch output stays unambiguous.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass

from . import config

ERR_RE = re.compile(r"ERROR (\d+) \(([0-9A-Z]{5})\)(?: at line \d+)?: (.*)")


@dataclass
class Result:
    rc: int
    out: str
    errno: int | None
    sqlstate: str | None
    error: str | None

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def rows(self) -> list[list[str]]:
        return [line.split("\t") for line in self.out.split("\n")] if self.out else []


class SqlError(RuntimeError):
    def __init__(self, label: str, result: Result):
        super().__init__(f"{label}: ERROR {result.errno} ({result.sqlstate}) {result.error}")
        self.result = result


def run(instance: str, account: str, sql: str, timeout: int = 600) -> Result:
    """Runs `sql` in one client session as `account`; stops at the first error."""
    cfg = config.load()
    proc = subprocess.run(
        [str(cfg.mysql_client), f"--defaults-extra-file={cfg.cnf(instance, account)}", "--batch",
         "--skip-column-names", "--raw", "--default-character-set=utf8mb4"],
        input=sql.encode("utf-8"), capture_output=True, timeout=timeout,
    )
    out = proc.stdout.decode("utf-8", "replace").replace("\r\n", "\n").rstrip("\n")
    err = proc.stderr.decode("utf-8", "replace").replace("\r\n", "\n").strip()
    m = ERR_RE.search(err)
    return Result(
        rc=proc.returncode,
        out=out,
        errno=int(m.group(1)) if m else None,
        sqlstate=m.group(2) if m else None,
        error=m.group(3).strip() if m else (err if proc.returncode else None),
    )


def must(instance: str, account: str, sql: str, label: str = "sql") -> Result:
    r = run(instance, account, sql)
    if not r.ok:
        raise SqlError(f"{label} as {account}@{instance}", r)
    return r


def scalar(instance: str, account: str, sql: str, label: str = "sql") -> str:
    out = must(instance, account, sql, label).out
    return out.split("\n")[-1] if out else ""


# --------------------------------------------------------------------------
# Literals and hex-wrapped selection
# --------------------------------------------------------------------------
def q(value) -> str:
    """SQL literal for a Python value (str, int, None)."""
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    return "'" + str(value).replace("\\", "\\\\").replace("'", "''") + "'"


def hx(expr: str) -> str:
    """Selects a scalar as hex of its character form; NULL stays distinguishable."""
    return f"IFNULL(HEX(CAST({expr} AS CHAR)), 'NULL')"


def hxb(expr: str) -> str:
    """Selects a binary or VECTOR value as hex of its bytes."""
    return f"IFNULL(HEX({expr}), 'NULL')"


def unhex_text(cell: str) -> str | None:
    return None if cell == "NULL" else bytes.fromhex(cell).decode("utf-8")


def unhex_bytes(cell: str) -> bytes | None:
    return None if cell == "NULL" else bytes.fromhex(cell)
