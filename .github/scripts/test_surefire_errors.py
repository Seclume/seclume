import os
import tempfile
import unittest
from pathlib import Path

import surefire_errors


def report(root, module, name, body):
    directory = Path(root) / module / "target" / "surefire-reports"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / f"TEST-{name}.xml").write_text(body, encoding="utf-8")


PASSING = '<testsuite><testcase classname="a.B" name="fine"/></testsuite>'
FAILING = """<testsuite>
  <testcase classname="space.seclume.crypto.ConstantTimeLeakageTest" name="theNegativeControlLeaks()">
    <failure type="org.opentest4j.AssertionFailedError" message="an early exit was not seen in 3 rounds (t = 1.00%)">
java.lang.AssertionError: wrapped
Caused by: java.io.IOException: first
Caused by: java.io.IOException: the last cause
    </failure>
  </testcase>
  <testcase classname="a.C" name="broken"><error type="java.lang.IllegalStateException" message="line one
line two"/></testcase>
  <testcase classname="a.D" name="threshold"><failure type="x" message="There are test failures. failure threshold"/></testcase>
</testsuite>"""


class SurefireErrorsTest(unittest.TestCase):

    def test_failures_and_errors_with_their_last_cause(self):
        with tempfile.TemporaryDirectory() as root:
            report(root, "seclume-core", "ok", PASSING)
            report(root, "seclume-core", "bad", FAILING)
            found = surefire_errors.errors(root)
        self.assertEqual(2, len(found))
        title, text = found[0]
        self.assertEqual("space.seclume.crypto.ConstantTimeLeakageTest.theNegativeControlLeaks()", title)
        self.assertTrue(text.startswith("Caused by: java.io.IOException: the last cause | "
                                        "org.opentest4j.AssertionFailedError: an early exit"), text)
        self.assertEqual(("a.C.broken", "java.lang.IllegalStateException: line one line two"), found[1],
                         "XML turns a line break in an attribute into a blank")

    def test_nested_modules_are_found(self):
        with tempfile.TemporaryDirectory() as root:
            report(os.path.join(root, "examples", "micronaut"), "", "x", FAILING)
            self.assertEqual(2, len(surefire_errors.errors(root)))

    def test_an_unreadable_report_is_reported_not_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            report(root, "m", "cut", "<testsuite><testcase")
            found = surefire_errors.errors(root)
        self.assertEqual(1, len(found))
        self.assertTrue(found[0][1].startswith("an unreadable report"), found)

    def test_an_annotation_is_one_line_escaped_and_bounded(self):
        line = surefire_errors.annotation("a.B.c(int, String)", "100% sure\r\nnot " + "x" * 2000)
        self.assertNotIn("\n", line)
        self.assertTrue(line.startswith("::error title=a.B.c(int%2C String)::100%25 sure  not "), line)
        self.assertLessEqual(len(line.split("::", 2)[2]), surefire_errors.LIMIT)
        self.assertIn("%3A", surefire_errors.annotation("a:b", "t"))

    def test_nothing_to_report(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual([], surefire_errors.errors(root))


if __name__ == "__main__":
    unittest.main()
