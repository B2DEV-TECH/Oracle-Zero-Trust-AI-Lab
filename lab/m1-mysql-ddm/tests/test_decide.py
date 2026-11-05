"""Verdict rules of verifier.decide() and the naive DLP baseline."""

import unittest

from m1 import fixtures, verifier


def facts(**over):
    f = {"hash_agreement": True, "code_match": True, "no_drift": True, "preflight_ok": True, "contract_ok": True,
         "declared_reader": True, "reader_equivalent": True, "world_ok": True, "aa_ok": True, "write_ok": True,
         "twins": [{"label": f"T{i}", "valid": True, "diverges": False} for i in range(1, 7)],
         "coverage_sufficient": True}
    f.update(over)
    return f


def checks(result):
    return [r["check"] for r in result["reasons"]]


class DecideTest(unittest.TestCase):
    def test_all_established_is_a_scoped_pass(self):
        r = verifier.decide(facts())
        self.assertEqual(r["verdict"], "PASS")
        self.assertIn("reader-equivalent", r["scope"])
        self.assertIn("6 tested twins", r["scope"])

    def test_privileged_identity_can_pass_on_twins(self):
        r = verifier.decide(facts(declared_reader=False, reader_equivalent=False))
        self.assertEqual(r["verdict"], "PASS")
        self.assertIn("privileged", r["scope"])

    def test_each_precondition_blocks_with_inconclusive(self):
        for key, check in [("hash_agreement", "integrity"), ("code_match", "code"), ("no_drift", "drift"),
                           ("preflight_ok", "preflight"), ("contract_ok", "contract"), ("world_ok", "world"),
                           ("aa_ok", "aa")]:
            for value in (False, None):
                r = verifier.decide(facts(**{key: value}))
                self.assertEqual(r["verdict"], "INCONCLUSIVE", key)
                self.assertEqual(checks(r), [check], key)

    def test_declared_reader_that_is_not_reader_equivalent(self):
        r = verifier.decide(facts(reader_equivalent=False))
        self.assertEqual((r["verdict"], checks(r)), ("INCONCLUSIVE", ["reader"]))

    def test_preconditions_take_precedence_over_divergence(self):
        tw = facts()["twins"]
        tw[0]["diverges"] = True
        r = verifier.decide(facts(aa_ok=False, twins=tw))
        self.assertEqual((r["verdict"], checks(r)), ("INCONCLUSIVE", ["aa"]))

    def test_divergence_in_a_valid_twin_fails(self):
        tw = facts()["twins"]
        tw[2]["diverges"] = True
        tw[4]["valid"] = False
        r = verifier.decide(facts(twins=tw, coverage_sufficient=False))
        self.assertEqual((r["verdict"], checks(r)), ("FAIL", ["twins"]))
        self.assertIn("T3", r["reasons"][0]["detail"])

    def test_divergence_in_an_invalid_twin_does_not_count(self):
        tw = facts()["twins"]
        tw[1].update(valid=False, diverges=True)
        r = verifier.decide(facts(twins=tw))
        self.assertEqual((r["verdict"], checks(r)), ("INCONCLUSIVE", ["twin_validity"]))

    def test_write_surface_fails(self):
        r = verifier.decide(facts(write_ok=False))
        self.assertEqual((r["verdict"], checks(r)), ("FAIL", ["write"]))

    def test_no_twins_or_low_coverage_is_inconclusive(self):
        self.assertEqual(checks(verifier.decide(facts(twins=[], coverage_sufficient=None))),
                         ["twin_validity", "coverage"])
        self.assertEqual(checks(verifier.decide(facts(coverage_sufficient=False))), ["coverage"])

    def test_missing_facts_never_pass(self):
        self.assertNotEqual(verifier.decide({})["verdict"], "PASS")


class DlpTest(unittest.TestCase):
    def setUp(self):
        self.world = {"suppliers": [[None if v is None else str(v) for v in r] for r in fixtures.suppliers()],
                      "invoices": []}

    def test_disclosed_note_is_flagged(self):
        note = fixtures.INVESTIGATION[3]
        chunks = [(1, "supplier:3", f"Profile. Compliance note: {note}.", b""), (2, "supplier:4", "Profile.", b"")]
        scan = verifier.dlp_scan(chunks, self.world)
        self.assertEqual(scan["flagged_chunks"], 1)
        self.assertIn("masked_value", scan["hits"]["supplier:3"])

    def test_omission_is_not_flagged(self):
        chunks = [(1, "supplier:1", "Synthetic Supplier Alpha is a industrial valves supplier.", b"")]
        self.assertEqual(verifier.dlp_scan(chunks, self.world)["flagged_chunks"], 0)


if __name__ == "__main__":
    unittest.main()
