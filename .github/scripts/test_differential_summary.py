import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from differential_summary import classes, main, table


def report(directory, cases):
    reports = Path(directory) / "seclume-diff" / "target" / "surefire-reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "TEST-x.xml").write_text("<testsuite>" + "".join(cases) + "</testsuite>")


CASES = [
    '<testcase classname="space.seclume.diff.OracleDifferentialTest" name="a"/>',
    '<testcase classname="space.seclume.diff.OracleDifferentialTest" name="b">'
    '<failure message="disagree" type="AssertionError"/></testcase>',
    '<testcase classname="space.seclume.diff.MySqlDifferentialTest" name="c">'
    '<skipped message="no .local-mysql-password"/></testcase>',
]


class DifferentialSummaryTest(unittest.TestCase):
    def test_each_class_is_counted_by_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, CASES)
            self.assertEqual(classes(directory), {"OracleDifferentialTest": [1, 0, 1],
                                                  "MySqlDifferentialTest": [0, 1, 0]})

    def test_the_summary_says_what_was_skipped(self):
        text = table("oracle", {"OracleDifferentialTest": [1, 0, 1],
                                "MySqlDifferentialTest": [0, 1, 0]})
        self.assertIn("2 classes: 1 passed, 1 failed, 1 skipped", text)
        self.assertIn("| MySqlDifferentialTest | 0 | 0 | 1 |", text)

    def test_failures_become_annotations(self):
        with tempfile.TemporaryDirectory() as directory:
            report(directory, CASES)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(main(["x", "oracle", directory]), 0)
            self.assertIn("::error title=space.seclume.diff.OracleDifferentialTest.b::", out.getvalue())

    def test_usage(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["x"]), 2)


if __name__ == "__main__":
    unittest.main()
