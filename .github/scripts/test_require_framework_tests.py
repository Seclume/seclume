import tempfile
import unittest
from pathlib import Path

from require_framework_tests import EXPECTED, require


class FrameworkGateTest(unittest.TestCase):
    def test_missing_skipped_and_failed_tests_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            with self.assertRaises(OSError):
                require("Postgres", reports)
            for framework, methods in EXPECTED.items():
                (reports / f"TEST-space.seclume.frameworks.{framework}OnPostgresTest.xml").write_text(
                    '<testsuite>' + ''.join(f'<testcase name="{method}"/>' for method in methods) + '</testsuite>')
            self.assertEqual(require("Postgres", reports), 9)
            file = reports / 'TEST-space.seclume.frameworks.JooqOnPostgresTest.xml'
            valid = file.read_text()
            for tag in ("skipped", "error", "failure"):
                file.write_text(valid.replace('/>', f'><{tag}/></testcase>', 1))
                with self.assertRaises(ValueError):
                    require("Postgres", reports)
