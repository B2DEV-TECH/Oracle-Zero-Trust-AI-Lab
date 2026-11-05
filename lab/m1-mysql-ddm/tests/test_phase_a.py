"""The phase A control: its deployment is 20_gate.sql without enforcement, and
every gate negative has a prediction written before the control ran."""

import re
import unittest
from collections import Counter

from m1 import negatives, phase_a, setup


class ControlDeployment(unittest.TestCase):
    def setUp(self):
        self.gate = (setup.SQL_DIR / "20_gate.sql").read_text(encoding="utf-8")
        self.control = setup.control_gate_sql()

    def test_tables_are_unchanged(self):
        self.assertEqual(self.control.split("DELIMITER //")[0], self.gate.split("DELIMITER //")[0])

    def test_functions_are_unchanged(self):
        for name in ("batch_hash", "pub_hash", "observation_state_hash", "identity_preconditions_ok"):
            pattern = rf"CREATE DEFINER[^\n]*FUNCTION m1_ctl\.{name}\(.*?END//"
            self.assertEqual(re.search(pattern, self.control, re.S).group(0),
                             re.search(pattern, self.gate, re.S).group(0), name)

    def test_no_trigger_and_a_release_procedure_without_checks(self):
        self.assertNotRegex(self.control, r"CREATE DEFINER[^\n]* TRIGGER ")
        self.assertEqual(len(re.findall(r"PROCEDURE m1_ctl\.release_batch\(", self.control)), 1)
        release = self.control[self.control.index("PROCEDURE m1_ctl.release_batch("):]
        self.assertNotIn("SIGNAL SQLSTATE", release)
        self.assertIn("SQL SECURITY DEFINER", release)


class Predictions(unittest.TestCase):
    def test_every_scenario_has_one_prediction(self):
        self.assertEqual(set(phase_a.PREDICTIONS), {s.sid for s in negatives.SCENARIOS})

    def test_registered_counts(self):
        counts = Counter(p[0] for p in phase_a.PREDICTIONS.values())
        self.assertEqual(counts, {phase_a.SUCCEEDED: 34, phase_a.MET: 17, phase_a.OTHER: 1,
                                  phase_a.NOT_EXECUTABLE: 2, phase_a.NOT_COMPARABLE: 1})
        admin = [sid for sid, p in phase_a.PREDICTIONS.items()
                 if p[0] == phase_a.SUCCEEDED and sid in phase_a.ADMINISTRATOR]
        self.assertEqual(len(admin), 10)


def row(sid, observed, result="FAIL"):
    return {"id": sid, "observed": observed, "result": result, "category": "c", "title": "t", "expected": "e"}


class Classification(unittest.TestCase):
    def test_classes(self):
        self.assertEqual(phase_a.observed_class(row("G03", "ERROR 1142 denied", "PASS")), phase_a.MET)
        self.assertEqual(phase_a.observed_class(row("G01", "ok")), phase_a.SUCCEEDED)
        self.assertEqual(phase_a.observed_class(row("G18", "setup failed: admin bypass")), phase_a.NOT_EXECUTABLE)
        self.assertEqual(phase_a.observed_class(row("G41", "ERROR 1062 Duplicate entry")), phase_a.OTHER)
        self.assertEqual(phase_a.observed_class(row("G40", "value False")), phase_a.NOT_COMPARABLE)

    def test_prediction_names_the_error_number(self):
        self.assertTrue(phase_a.held(row("G41", "ERROR 1062 Duplicate entry '7-1'")))
        self.assertFalse(phase_a.held(row("G41", "ERROR 1644 M1 gate: batch already released")))
        self.assertTrue(phase_a.held(row("G18", "setup failed: admin bypass as root@lab: ERROR 1360 (HY000) "
                                                "Trigger does not exist")))

    def test_gate_adds_only_where_the_gate_refused(self):
        control = {"scenarios": [row(sid, "ok") if p[0] == phase_a.SUCCEEDED else row(sid, "x", "PASS")
                                 for sid, p in phase_a.PREDICTIONS.items()]}
        gate = {"scenarios": [row(sid, "ERROR 1644", "PASS") for sid in phase_a.PREDICTIONS]}
        gate["scenarios"][0]["result"] = "FAIL"  # G01: suppose the gate had not refused it
        s = phase_a.compare(control, gate)["summary"]
        self.assertEqual(s["gate_adds"], 33)
        self.assertNotIn("G01", s["gate_adds_ids"])


if __name__ == "__main__":
    unittest.main()
