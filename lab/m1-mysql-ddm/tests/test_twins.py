"""Twin planning and repair against fake oracles. The real oracle is the
agent's session on the shadow instance; these tests only pin the logic."""

import unittest
from unittest import mock

from m1 import fixtures, twins

COLS = twins.COLUMNS


def rows():
    return [[None if v is None else str(v) for v in r] for r in fixtures.suppliers()]


def masked(row):
    out = list(row)
    out[COLS.index("tax_id")] = "***-***-" + row[COLS.index("tax_id")][-4:]
    out[COLS.index("compliance_note")] = "[RESTRICTED]"
    out[COLS.index("risk_score")] = "0"
    return out


def oracle(mask):
    return lambda candidate: {"suppliers": [mask(r) for r in candidate], "invoices": []}


class TwinTest(unittest.TestCase):
    def test_plan_never_offers_the_original_value(self):
        base = rows()
        for twin in twins.plan(base, seed=7):
            for (r, col), tiers in twin.candidates.items():
                self.assertNotIn(base[r][COLS.index(col)], tiers)
                self.assertEqual(len(tiers), len(set(map(repr, tiers))))

    def test_plan_refuses_masked_column_without_generator(self):
        with mock.patch.dict(twins.GENERATORS, clear=True):
            with self.assertRaises(ValueError):
                twins.plan(rows(), seed=1)

    def test_faithful_oracle_gives_valid_repaired_twins_with_coverage(self):
        base, view_of = rows(), oracle(masked)
        realised = [twins.realise(base, view_of(base), t, view_of) for t in twins.plan(base, seed=11)]
        self.assertTrue(all(r.valid for r in realised))
        for r in realised:
            self.assertEqual(view_of(r.rows), view_of(base))
            self.assertNotEqual(r.rows, base)
        # a value from another row shows another last-4 suffix, so permutation twins need repair
        self.assertTrue(any(r.repaired for r in realised if r.twin.kind == "permutation"))
        self.assertTrue(twins.coverage(base, realised)["sufficient"])

    def test_oracle_that_shows_null_leaves_cells_uncovered(self):
        def leaky(row):
            out = masked(row)
            if row[COLS.index("compliance_note")] is None:
                out[COLS.index("compliance_note")] = None
            return out

        base, view_of = rows(), oracle(leaky)
        realised = [twins.realise(base, view_of(base), t, view_of) for t in twins.plan(base, seed=11)]
        note = COLS.index("compliance_note")
        for r in realised:
            # exhausted cells fall back to the original value, so the twin stays indistinguishable
            self.assertTrue(r.valid)
            self.assertEqual(view_of(r.rows), view_of(base))
            self.assertTrue(all((a[note] is None) == (b[note] is None) for a, b in zip(r.rows, base)))
        cov = twins.coverage(base, realised)
        self.assertLess(cov["columns"]["compliance_note"]["share"], 0.8)
        self.assertFalse(cov["sufficient"])

    def test_difference_in_unmasked_column_is_not_repaired(self):
        def derived(row):
            out = masked(row)
            if int(row[COLS.index("risk_score")]) >= 70:
                out[COLS.index("region")] += "*"
            return out

        base, view_of = rows(), oracle(derived)
        realised = [twins.realise(base, view_of(base), t, view_of) for t in twins.plan(base, seed=3)]
        self.assertTrue(all(not r.valid for r in realised))
        self.assertTrue(all(cell[1] == "region" for r in realised for cell in r.unrepairable))

    def test_coverage_insufficient_with_one_partial_twin(self):
        base = rows()
        changed = [list(r) for r in base]
        changed[0][COLS.index("risk_score")] = "99"
        r = twins.Realised(twins.Twin("T1", "synthetic"), changed, True, 1, 0, 0)
        cov = twins.coverage(base, [r])
        self.assertFalse(cov["sufficient"])
        self.assertEqual(cov["columns"]["risk_score"]["rows_covered"], 1)
        self.assertFalse(twins.coverage(base, [])["sufficient"])


if __name__ == "__main__":
    unittest.main()
