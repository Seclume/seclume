"""Tests for coverage_merge.py: which data goes into which module's report."""

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import coverage_merge  # noqa: E402


class CoverageMergeTest(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.artifacts = root / "artifacts"
        self.repository = root / "repo"
        for job, modules in (("core", ["seclume-core", "seclume-pool"]),
                             ("postgresql", ["seclume-core", "seclume-postgresql"])):
            for module in modules:
                target = self.artifacts / f"coverage-exec-{job}" / module / "target"
                (target / "classes").mkdir(parents=True)
                (target / "jacoco.exec").write_bytes(b"\x01")
        # A job whose module was compiled but recorded nothing: no exec, no entry.
        (self.artifacts / "coverage-exec-oracle" / "seclume-oracle" / "target" / "classes").mkdir(
            parents=True)
        for module in ("seclume-core", "seclume-postgresql"):
            (self.repository / module / "src" / "main" / "java").mkdir(parents=True)
        self.root = root

    def tearDown(self):
        self.dir.cleanup()

    def test_every_job_that_recorded_a_module_is_kept_and_a_module_only_compiled_too(self):
        modules = coverage_merge.plan(self.artifacts)
        self.assertEqual({"seclume-core", "seclume-pool", "seclume-postgresql", "seclume-oracle"},
                         set(modules))
        self.assertEqual(["core", "postgresql"], modules["seclume-core"]["jobs"])
        self.assertEqual(2, len(modules["seclume-core"]["exec"]))
        self.assertIn("coverage-exec-core", str(modules["seclume-core"]["classes"]))
        # Compiled in the oracle job, no tests of its own there: its code may
        # still have run under another module's.
        self.assertEqual([], modules["seclume-oracle"]["exec"])
        self.assertIsNotNone(modules["seclume-oracle"]["classes"])

    def test_every_modules_data_goes_into_every_modules_report(self):
        modules = coverage_merge.plan(self.artifacts)
        steps = coverage_merge.commands(modules, self.repository, "cli.jar")
        # One merge of all four files, then a report for each module with sources here.
        self.assertEqual([None, "seclume-core", "seclume-postgresql"], list(steps))
        (merge,) = steps[None]
        self.assertEqual(["java", "-jar", "cli.jar", "merge"], merge[:4])
        self.assertEqual(4, sum(1 for part in merge if part.endswith("jacoco.exec")))
        destination = merge[merge.index("--destfile") + 1]
        (report,) = steps["seclume-postgresql"]
        self.assertEqual(destination, report[4], "the report reads the merge of everything")
        self.assertIn("--classfiles", report)
        self.assertTrue(report[report.index("--xml") + 1].endswith(
            "seclume-postgresql/target/site/jacoco/jacoco.xml"))

    def test_nothing_recorded_means_no_report(self):
        empty = self.root / "empty"
        (empty / "coverage-exec-core" / "seclume-core" / "target" / "classes").mkdir(parents=True)
        self.assertEqual({}, coverage_merge.commands(coverage_merge.plan(empty),
                                                     self.repository, "cli.jar"))

    def test_a_failed_merge_fails_the_step_and_a_mismatch_is_counted(self):
        calls = []

        def failing(step, **_):
            calls.append(step)
            return subprocess.CompletedProcess(step, 1, "", "broken")

        # What it prints are annotations; not on this run, whose failure it is not.
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(1, coverage_merge.main(
                [str(self.artifacts), str(self.repository), "cli.jar"], run=failing))
        self.assertIn("::error title=coverage", printed.getvalue())
        self.assertEqual(1, len(calls))

        def mismatching(step, **_):
            return subprocess.CompletedProcess(step, 0, "[WARN] Execution data for class a/B "
                                               "does not match.", "")

        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            self.assertEqual(0, coverage_merge.main(
                [str(self.artifacts), str(self.repository), "cli.jar"], run=mismatching))
        self.assertIn("::warning title=coverage::3 classes", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
