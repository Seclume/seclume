"""Tests for coverage_report.py: counted from JaCoCo's XML, nothing made up."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import coverage_report  # noqa: E402

REPORT = """<?xml version="1.0" encoding="UTF-8"?>
<report name="m">
  <package name="space/seclume/secret">
    <counter type="LINE" missed="10" covered="90"/>
    <counter type="BRANCH" missed="5" covered="15"/>
  </package>
  <package name="space/seclume/secret/inner">
    <counter type="LINE" missed="0" covered="10"/>
  </package>
  <package name="space/seclume/other">
    <counter type="LINE" missed="50" covered="50"/>
  </package>
  <counter type="LINE" missed="60" covered="150"/>
  <counter type="BRANCH" missed="5" covered="15"/>
</report>
"""


class CoverageReportTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        for module in ("with-report", "without-report"):
            (root / module / "src" / "main" / "java").mkdir(parents=True)
            (root / module / "pom.xml").write_text("<project/>")
        (root / "parent-only").mkdir()
        (root / "parent-only" / "pom.xml").write_text("<project/>")
        jacoco = root / "with-report" / "target" / "site" / "jacoco"
        jacoco.mkdir(parents=True)
        (jacoco / "jacoco.xml").write_text(REPORT)
        (root / ".github").mkdir()
        (root / ".github" / "coverage-critical.json").write_text(json.dumps([
            {"package": "space.seclume.secret", "why": "secrets"},
            {"package": "space.seclume.tls", "why": "tls"}]))
        self.root = root

    def tearDown(self):
        self.dir.cleanup()

    def test_modules_are_counted_and_a_missing_report_is_said(self):
        modules = coverage_report.collect(self.root)
        self.assertEqual({"with-report", "without-report"}, set(modules))
        self.assertIsNone(modules["without-report"])
        self.assertEqual((60, 150), modules["with-report"]["totals"]["LINE"])
        text = coverage_report.markdown(modules, {})
        self.assertIn("| with-report | 210 | 71.4 % | 20 | 75.0 % |", text)
        self.assertIn("| without-report | - | no report | - | - |", text)

    def test_a_critical_package_sums_its_subpackages_and_nothing_else(self):
        modules = coverage_report.collect(self.root)
        critical = coverage_report.critical_packages(modules, [
            {"package": "space.seclume.secret", "why": "s"},
            {"package": "space.seclume.tls", "why": "t"}])
        self.assertEqual((10, 100), critical["space.seclume.secret"]["LINE"])
        self.assertEqual((5, 15), critical["space.seclume.secret"]["BRANCH"])
        self.assertFalse(critical["space.seclume.tls"]["found"])
        text = coverage_report.markdown(modules, critical)
        self.assertIn("| `space.seclume.secret` | s | 90.9 % | 75.0 % |", text)
        self.assertIn("| `space.seclume.tls` | t | no report | - |", text)

    def test_the_json_carries_the_counts(self):
        out = self.root / "coverage.json"
        coverage_report.main([str(self.root), "--json", str(out)])
        data = json.loads(out.read_text())
        self.assertEqual({"missed": 60, "covered": 150}, data["modules"]["with-report"]["line"])
        self.assertIsNone(data["modules"]["without-report"])
        self.assertEqual({"missed": 10, "covered": 100},
                         data["critical"]["space.seclume.secret"]["line"])


if __name__ == "__main__":
    unittest.main()
