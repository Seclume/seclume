import tempfile
import unittest
from pathlib import Path

from require_replication_tests import SUITES, main, problems, read_report


def write(directory, suite, cases):
    """A Surefire report of ``suite`` with ``cases``: name -> None, or the outcome's tag."""
    body = "".join(
        f'<testcase name="{name}">' + (f"<{outcome}/>" if outcome else "") + "</testcase>"
        for name, outcome in cases.items())
    (Path(directory) / f"TEST-space.seclume.pool.{suite}.xml").write_text(
        f"<testsuite>{body}</testsuite>", encoding="utf-8")


class RequiredReplicationTestsTest(unittest.TestCase):
    def test_both_suites_run_and_passed(self):
        with tempfile.TemporaryDirectory() as directory:
            for suite in SUITES:
                write(directory, suite, {"readsWait": None, "readsFallBack": None})
            self.assertEqual([], problems(Path(directory)))
            self.assertEqual(0, main([directory]))

    def test_a_missing_report_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            write(directory, SUITES[0], {"readsWait": None})
            errors = problems(Path(directory))
            self.assertEqual(1, len(errors))
            self.assertIn("missing report", errors[0])
            self.assertIn(SUITES[1], errors[0])
            self.assertEqual(1, main([directory]))

    def test_a_skipped_test_is_what_this_is_here_to_catch(self):
        with tempfile.TemporaryDirectory() as directory:
            write(directory, SUITES[0], {"readsWait": "skipped"})
            write(directory, SUITES[1], {"readsWait": None})
            self.assertEqual([f"{SUITES[0]}.readsWait: skipped"], problems(Path(directory)))

    def test_failures_errors_and_empty_suites_are_named(self):
        with tempfile.TemporaryDirectory() as directory:
            write(directory, SUITES[0], {"a": "failure", "b": "error", "c": None})
            write(directory, SUITES[1], {})
            self.assertEqual([f"{SUITES[0]}.a: failure", f"{SUITES[0]}.b: error",
                              f"{SUITES[1]}: no test ran"], problems(Path(directory)))

    def test_dtd_and_entity_input_is_rejected_before_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.xml"
            report.write_text('<!DOCTYPE testsuite [<!ENTITY x "y">]><testsuite>&x;</testsuite>',
                              encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "DTD/entity"):
                read_report(report)


if __name__ == "__main__":
    unittest.main()
