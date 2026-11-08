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

    def test_every_job_that_recorded_a_module_goes_into_its_report(self):
        modules = coverage_merge.plan(self.artifacts)
        self.assertEqual({"seclume-core", "seclume-pool", "seclume-postgresql"}, set(modules))
        self.assertEqual(["core", "postgresql"], modules["seclume-core"]["jobs"])
        self.assertEqual(2, len(modules["seclume-core"]["exec"]))
        self.assertIn("coverage-exec-core", str(modules["seclume-core"]["classes"]))
        self.assertNotIn("seclume-oracle", modules)

    def test_a_module_without_sources_here_gets_no_report(self):
        modules = coverage_merge.plan(self.artifacts)
        steps = coverage_merge.commands(modules, self.repository, "cli.jar")
        self.assertEqual({"seclume-core", "seclume-postgresql"}, set(steps))
        merge, report = steps["seclume-core"]
        self.assertEqual(["java", "-jar", "cli.jar", "merge"], merge[:4])
        self.assertEqual(2, sum(1 for part in merge if part.endswith("jacoco.exec")))
        self.assertIn("--classfiles", report)
        self.assertTrue(report[report.index("--xml") + 1].endswith(
            "seclume-core/target/site/jacoco/jacoco.xml"))

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
        self.assertIn("::warning title=coverage::4 classes", printed.getvalue())


if __name__ == "__main__":
    unittest.main()
