"""Tests for coverage_gate.py: a floor holds, and nothing passes for want of data."""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import coverage_gate  # noqa: E402


def numbers(covered, total):
    return {"missed": total - covered, "covered": covered}


REPORT = {
    "total": {"line": numbers(800, 1000), "branch": numbers(70, 100)},
    "modules": {
        "seclume-core": {"line": numbers(790, 1000), "branch": numbers(70, 100)},
        "seclume-pool": {"line": numbers(90, 100), "branch": numbers(0, 0)},
        "seclume-new": {"line": numbers(5, 10), "branch": numbers(1, 2)},
        "seclume-quiet": None,
    },
    "critical": {
        "space.seclume.secret": {"why": "w", "line": numbers(81, 100), "branch": numbers(73, 100)},
        "space.seclume.gone": {"why": "w"},
    },
}


def run(report, floors):
    with tempfile.TemporaryDirectory() as directory:
        report_file = Path(directory) / "report.json"
        floors_file = Path(directory) / "floors.json"
        report_file.write_text(json.dumps(report), encoding="utf-8")
        floors_file.write_text(json.dumps(floors), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = coverage_gate.main([str(report_file), str(floors_file)])
        return code, out.getvalue(), err.getvalue()


class CoverageGateTest(unittest.TestCase):

    def test_at_or_above_every_floor_passes(self):
        code, out, _ = run(REPORT, {"total": {"line": 80, "branch": 70},
                                    "modules": {"seclume-core": {"line": 79, "branch": 70}},
                                    "packages": {"space.seclume.secret": {"line": 81, "branch": 73}}})
        self.assertEqual(0, code, out)
        self.assertNotIn("::error", out)

    def test_below_a_floor_fails_and_names_the_module(self):
        code, out, err = run(REPORT, {"modules": {"seclume-core": {"line": 80, "branch": 60}}})
        self.assertEqual(1, code)
        self.assertIn("::error title=coverage (seclume-core)::seclume-core: line coverage 79.0 %", out)
        self.assertNotIn("branch coverage 70.0 % is below", out)
        self.assertIn("seclume-core", err)

    def test_a_critical_package_below_its_floor_fails(self):
        code, out, _ = run(REPORT, {"packages": {"space.seclume.secret": {"line": 90}}})
        self.assertEqual(1, code)
        self.assertIn("::error title=coverage (space.seclume.secret)::", out)

    def test_a_module_that_stopped_recording_fails(self):
        code, out, _ = run(REPORT, {"modules": {"seclume-quiet": {"line": 50}}})
        self.assertEqual(1, code)
        self.assertIn("no coverage was measured", out)

    def test_a_package_without_numbers_fails(self):
        code, out, _ = run(REPORT, {"packages": {"space.seclume.gone": {"line": 50}}})
        self.assertEqual(1, code)
        self.assertIn("no coverage was measured", out)

    def test_a_floor_for_a_module_the_report_does_not_know_fails(self):
        code, out, _ = run(REPORT, {"modules": {"seclume-renamed": {"line": 50}},
                                    "packages": {"space.seclume.renamed": {"line": 50}}})
        self.assertEqual(1, code)
        self.assertIn("::error title=coverage (seclume-renamed)::", out)
        self.assertIn("::error title=coverage (space.seclume.renamed)::", out)

    def test_nothing_to_cover_is_not_a_failure(self):
        code, out, _ = run(REPORT, {"modules": {"seclume-pool": {"line": 89, "branch": 99}}})
        self.assertEqual(0, code, out)
        self.assertIn("nothing to cover", out)

    def test_a_module_without_a_floor_is_a_warning_only(self):
        code, out, _ = run(REPORT, {"modules": {"seclume-core": {"line": 1}}})
        self.assertEqual(0, code)
        self.assertIn("::warning title=coverage (seclume-new)::", out)
        self.assertIn("::warning title=coverage (seclume-pool)::", out)
        self.assertNotIn("(seclume-quiet)", out.split("Modules measured without a floor")[-1])

    def test_a_floor_well_below_the_measurement_can_be_raised(self):
        code, out, _ = run(REPORT, {"modules": {"seclume-core": {"line": 70}}})
        self.assertEqual(0, code)
        self.assertIn("::notice title=coverage (seclume-core)::", out)
        self.assertIn("raised to 78 %", out)
        _, out, _ = run(REPORT, {"modules": {"seclume-core": {"line": 77}}})
        self.assertNotIn("::notice", out)

    def test_the_repositorys_floors_file_reads_and_covers_the_critical_packages(self):
        root = Path(__file__).resolve().parents[2]
        floors = json.loads((root / ".github" / "coverage-floors.json").read_text(encoding="utf-8"))
        critical = json.loads((root / ".github" / "coverage-critical.json").read_text(encoding="utf-8"))
        self.assertEqual(sorted(entry["package"] for entry in critical), sorted(floors["packages"]))
        for name, floor in list(floors["modules"].items()) + list(floors["packages"].items()):
            self.assertTrue((root / name / "pom.xml").is_file() or name.startswith("space.seclume."), name)
            for kind, value in floor.items():
                self.assertIn(kind, ("line", "branch"), name)
                self.assertTrue(0 <= value <= 100, f"{name} {kind} {value}")


if __name__ == "__main__":
    unittest.main()
