import tempfile
import unittest
from pathlib import Path

from require_testcase import passed


def report(directory, body):
    path = Path(directory) / "TEST-x.xml"
    path.write_text(f"<testsuite>{body}</testsuite>", encoding="utf-8")
    return [str(path)]


class RequiredTestcaseTest(unittest.TestCase):
    def test_output_written_by_a_passing_case_is_no_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = report(directory, '<testcase name="a(Db)[1]">'
                           "<system-err>WARNING: tls=prefer</system-err></testcase>")
            self.assertTrue(passed(paths, "a(Db)[1]")[0])

    def test_a_skipped_failed_or_missing_case_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = report(directory, '<testcase name="s"><skipped/></testcase>'
                           '<testcase name="f"><failure message="x"/></testcase>'
                           '<testcase name="e"><error message="x"/></testcase>')
            for name in ("s", "f", "e", "absent"):
                with self.subTest(name=name):
                    self.assertFalse(passed(paths, name)[0])

    def test_no_report_is_not_a_pass(self):
        self.assertFalse(passed([], "a")[0])

    def test_entities_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "TEST-x.xml"
            path.write_text('<!DOCTYPE t [<!ENTITY x "y">]><testsuite/>', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DTD/entity"):
                passed([str(path)], "a")


if __name__ == "__main__":
    unittest.main()
