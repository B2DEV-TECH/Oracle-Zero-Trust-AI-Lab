"""Twin worlds: copies of the source data that differ only in masked values
and look identical to the agent.

A twin is never trusted to be indistinguishable because of how the masks are
believed to work. Each candidate twin is loaded into the shadow instance and
read back as the agent (the oracle). Any masked cell whose agent-visible form
differs from the original is moved to its next candidate value; when no
candidate is left the cell keeps its original value and counts as not
covered. A twin whose agent view still differs is invalid.

Candidate tiers per masked cell, without values equal to the original:
    permutation twin: value from another row of the same column, then a synthetic value
    synthetic twin:   synthetic value, then a value from another row
"""

from __future__ import annotations

import random
import string
from dataclasses import dataclass, field

from .fixtures import MASKED, TABLES

TABLE = "suppliers"
COLUMNS = TABLES[TABLE][1]
MASKED_COLUMNS = MASKED[TABLE]

Row = list  # values as text or None, in COLUMNS order
Cell = tuple[int, str]  # row index, column name


def _synthetic_tax_id(rng: random.Random, original: str) -> str:
    """Same length and last four characters; letters and digits elsewhere replaced."""
    head = "".join(rng.choice(string.ascii_uppercase) if ch.isalpha() else
                   rng.choice(string.digits) if ch.isdigit() else ch for ch in original[:-4])
    return head + original[-4:]


_TOPICS = ["vendor master change", "duplicate payment", "unapproved discount", "missing tax certificate",
           "related-party contract", "split purchase order", "expired insurance", "backdated invoice"]


def _synthetic_note(rng: random.Random, original: str | None) -> str | None:
    kind = rng.randrange(3)
    if kind == 0:
        return None
    topic = rng.choice(_TOPICS)
    if kind == 1:
        return f"Synthetic review: {topic} under investigation (case SYN-TW-{rng.randrange(10000):04d})"
    return f"Synthetic review: {topic} checked and closed"


def _synthetic_risk(rng: random.Random, original: str) -> str:
    return str(rng.randrange(101))


GENERATORS = {"tax_id": _synthetic_tax_id, "compliance_note": _synthetic_note, "risk_score": _synthetic_risk}


@dataclass
class Twin:
    label: str
    kind: str  # "permutation" or "synthetic"
    candidates: dict[Cell, list] = field(default_factory=dict)


def _derangement(rng: random.Random, n: int) -> list[int]:
    while True:
        p = list(range(n))
        rng.shuffle(p)
        if all(p[i] != i for i in range(n)):
            return p


def plan(rows: list[Row], seed: int, permutations: int = 3, synthetic: int = 3) -> list[Twin]:
    missing = [c for c in MASKED_COLUMNS if c not in GENERATORS]
    if missing:
        raise ValueError(f"no twin generator for masked columns: {missing}")
    rng = random.Random(seed)
    twins = []
    for n, kind in enumerate(["permutation"] * permutations + ["synthetic"] * synthetic, start=1):
        twin = Twin(label=f"T{n}", kind=kind)
        for col in MASKED_COLUMNS:
            ci = COLUMNS.index(col)
            perm = _derangement(rng, len(rows))
            for r, row in enumerate(rows):
                original = row[ci]
                permuted = rows[perm[r]][ci]
                synthetic_value = GENERATORS[col](rng, original)
                order = [permuted, synthetic_value] if kind == "permutation" else [synthetic_value, permuted]
                tiers = []
                for value in order:
                    if value != original and value not in tiers:
                        tiers.append(value)
                twin.candidates[(r, col)] = tiers
        twins.append(twin)
    return twins


def materialise(rows: list[Row], twin: Twin, choice: dict[Cell, int]) -> list[Row]:
    out = [list(r) for r in rows]
    for (r, col), tiers in twin.candidates.items():
        k = choice.get((r, col), 0)
        if k < len(tiers):
            out[r][COLUMNS.index(col)] = tiers[k]
    return out


@dataclass
class Realised:
    twin: Twin
    rows: list[Row]
    valid: bool
    rounds: int
    repaired: int        # cells moved to a later tier
    uncovered: int       # masked cells left at their original value
    unrepairable: list = field(default_factory=list)


def realise(rows: list[Row], base_view, twin: Twin, view_of, max_rounds: int = 4) -> Realised:
    """view_of(candidate_rows) returns the agent's view of the full source
    (a dict table -> rows, suppliers in COLUMNS order). base_view is the
    agent's view of the original rows."""
    choice = {cell: 0 for cell in twin.candidates}
    repaired = 0
    for rnd in range(1, max_rounds + 1):
        candidate = materialise(rows, twin, choice)
        view = view_of(candidate)
        bad_cells, other_diffs = [], []
        for table, base_rows in base_view.items():
            if view.get(table) == base_rows:
                continue
            if table != TABLE or len(view.get(table, [])) != len(base_rows):
                other_diffs.append(table)
                continue
            for r, (seen, expected) in enumerate(zip(view[table], base_rows)):
                for ci, (a, b) in enumerate(zip(seen, expected)):
                    if a != b:
                        col = COLUMNS[ci]
                        (bad_cells if col in MASKED_COLUMNS else other_diffs).append((r, col))
        if not bad_cells and not other_diffs:
            uncovered = sum(1 for cell, tiers in twin.candidates.items() if choice[cell] >= len(tiers))
            return Realised(twin, candidate, True, rnd, repaired, uncovered)
        if other_diffs:
            return Realised(twin, candidate, False, rnd, repaired, 0, other_diffs)
        stuck = [cell for cell in bad_cells if choice[cell] >= len(twin.candidates[cell])]
        if stuck:
            return Realised(twin, candidate, False, rnd, repaired, 0, stuck)
        for cell in bad_cells:
            choice[cell] += 1
            repaired += 1
    return Realised(twin, materialise(rows, twin, choice), False, max_rounds, repaired, 0, ["max rounds"])


def coverage(rows: list[Row], realised: list[Realised], minimum: float = 0.8) -> dict:
    """Per masked column: rows changed in each valid twin and the share of rows
    changed in at least one of them. Sufficient when every valid twin changes
    every masked column and each column's share reaches `minimum`."""
    valid = [t for t in realised if t.valid]
    report, ok = {}, bool(valid)
    for col in MASKED_COLUMNS:
        ci = COLUMNS.index(col)
        per_twin = {t.twin.label: [r for r in range(len(rows)) if t.rows[r][ci] != rows[r][ci]] for t in valid}
        union = set().union(*per_twin.values()) if per_twin else set()
        share = len(union) / len(rows) if rows else 0.0
        report[col] = {"changed_per_twin": {k: len(v) for k, v in per_twin.items()},
                       "rows_covered": len(union), "rows": len(rows), "share": round(share, 4)}
        ok = ok and share >= minimum and all(per_twin.values())
    return {"columns": report, "minimum_share": minimum, "sufficient": ok}
