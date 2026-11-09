"""Judging of gate negatives that also check what reached publication."""

import unittest

from m1 import db, negatives, setup


def result(errno=None, error=None):
    return db.Result(rc=0 if errno is None else 1, out="", errno=errno,
                     sqlstate=None if errno is None else "45000", error=error)


def state(published, releases, quarantined=2):
    return dict(published_rows=published, release_records=releases, quarantine_rows=quarantined)


REFUSED = result(1644, "M1 gate: " + negatives.SOURCE_ALTERED)
UNPUBLISHED = negatives.err_unpublished(1644, negatives.SOURCE_ALTERED)


class Unpublished(unittest.TestCase):
    def test_refused_and_absent(self):
        self.assertTrue(negatives._judge(UNPUBLISHED, (REFUSED, state(0, 0)))[0])

    def test_released_is_a_failure(self):
        passed, seen, st = negatives._judge(UNPUBLISHED, (result(), state(2, 1)))
        self.assertFalse(passed)
        self.assertEqual(seen, "ok")
        self.assertEqual(st["published_rows"], 2)

    def test_refused_for_another_reason(self):
        other = result(1644, "M1 gate: observation state changed since the verification")
        self.assertFalse(negatives._judge(UNPUBLISHED, (other, state(0, 0)))[0])

    def test_refused_but_something_published(self):
        self.assertFalse(negatives._judge(UNPUBLISHED, (REFUSED, state(2, 0)))[0])
        self.assertFalse(negatives._judge(UNPUBLISHED, (REFUSED, state(0, 1)))[0])


class Published(unittest.TestCase):
    def test_every_row_and_one_record(self):
        self.assertTrue(negatives._judge(negatives.PUBLISHED, (result(), state(2, 1)))[0])

    def test_partial_missing_or_refused(self):
        self.assertFalse(negatives._judge(negatives.PUBLISHED, (result(), state(1, 1)))[0])
        self.assertFalse(negatives._judge(negatives.PUBLISHED, (result(), state(2, 0)))[0])
        self.assertFalse(negatives._judge(negatives.PUBLISHED, (result(), state(0, 1, 0)))[0])
        self.assertFalse(negatives._judge(negatives.PUBLISHED, (REFUSED, state(0, 0)))[0])


class Unchanged(unittest.TestCase):
    def test_plain_expectations_report_no_state(self):
        self.assertEqual(negatives._judge(negatives.OK, result()), (True, "ok", None))
        self.assertEqual(negatives._judge(negatives.err(1142), result(1142, "denied")),
                         (True, "ERROR 1142 denied", None))


class Message(unittest.TestCase):
    def test_the_expected_refusal_is_the_release_procedure_message(self):
        gate_sql = (setup.SQL_DIR / "20_gate.sql").read_text(encoding="utf-8")
        self.assertIn(f"'M1 gate: {negatives.SOURCE_ALTERED}'", gate_sql)


if __name__ == "__main__":
    unittest.main()
