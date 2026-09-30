import tempfile
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

from require_pool_tests import require


class RequiredPoolTestsTest(unittest.TestCase):
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
