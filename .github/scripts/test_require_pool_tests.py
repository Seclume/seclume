import tempfile
import unittest
from pathlib import Path
# Only constructs and serializes synthetic test fixtures; never parses input.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

from require_pool_tests import read_report, require


class RequiredPoolTestsTest(unittest.TestCase):
    def test_dtd_and_entity_input_is_rejected_before_parsing(self):
        for document in (
            '<!DOCTYPE testsuite [<!ENTITY x SYSTEM "file:///etc/passwd">]><testsuite>&x;</testsuite>',
            '<!ENTITY x "expansion"><testsuite/>',
            '<\x00!DOCTYPE testsuite><testsuite/>',
        ):
            with self.subTest(document=document), tempfile.TemporaryDirectory() as directory:
                report = Path(directory) / "report.xml"
                report.write_text(document, encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "DTD/entity"):
                    read_report(report)

    def test_missing_report_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "missing report"):
                require("MySQL", Path(directory))

    def test_all_required_cases_must_exist_and_pass(self):
        names = [
            "theNextBorrowerDoesNotInheritTheTenant",
            "aConnectionThatSetNothingGoesBackAsItWas",
            "statementsLeftOpenAreClosedOnReturnAndCounted",
            "hiddenProcedureStateDoesNotReachTheNextBorrower",
        ]
        for outcome in (None, "skipped", "failure", "error", "missing"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = ET.Element("testsuite")
                for index, name in enumerate(names):
                    if index == 3 and outcome == "missing":
                        continue
                    case = ET.SubElement(root, "testcase", name=f"{name}(Db)[2]")
                    if index == 3 and outcome:
                        ET.SubElement(case, outcome)
                # Unavailable databases in this job do not satisfy or fail its gate.
                case = ET.SubElement(root, "testcase", name=f"{names[0]}(Db)[1]")
                ET.SubElement(case, "skipped")
                report = Path(directory) / "TEST-space.seclume.pool.SessionResetTest.xml"
                ET.ElementTree(root).write(report)
                if outcome is None:
                    self.assertEqual(4, require("MySQL", Path(directory)))
                else:
                    with self.assertRaises(ValueError):
                        require("MySQL", Path(directory))


if __name__ == "__main__":
    unittest.main()
