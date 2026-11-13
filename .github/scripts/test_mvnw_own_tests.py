import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent / "mvnw-own-tests.sh"


class MvnwOwnTestsTest(unittest.TestCase):
    """mvnw-own-tests.sh against a stand-in mvnw-retry.sh that records its calls."""

    def run_with(self, *arguments, codes=(0, 0)):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            retry = work / "retry.sh"
            retry.write_text(
                "#!/usr/bin/env bash\n"
                "n=$(( $(cat count 2>/dev/null || echo 0) + 1 )); echo $n > count\n"
                "printf '%s\\n' \"$*\" >> calls\n"
                f"codes=({' '.join(str(c) for c in codes)})\n"
                "exit ${codes[$((n-1))]:-0}\n")
            retry.chmod(retry.stat().st_mode | stat.S_IEXEC)
            result = subprocess.run(["bash", str(WRAPPER), *arguments], cwd=work, capture_output=True,
                                    text=True, env={**os.environ, "MVNW_RETRY": str(retry)}, timeout=60)
            calls = (work / "calls").read_text().splitlines() if (work / "calls").exists() else []
            return result, calls

    def test_the_needed_modules_are_installed_without_tests_and_only_the_named_ones_tested(self):
        result, calls = self.run_with("-B", "-Pcoverage", "-pl", "seclume-postgresql,seclume-pool", "-am",
                                      "test", "-Dseclume.pg.port=5432")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual([
            "-B -Pcoverage -pl seclume-postgresql,seclume-pool -am install -DskipTests -Dseclume.pg.port=5432",
            "-B -Pcoverage -pl seclume-postgresql,seclume-pool test -Dseclume.pg.port=5432",
        ], calls)

    def test_a_test_filter_stays_with_the_tests(self):
        result, calls = self.run_with("-B", "-pl", "seclume-pool", "-am", "test",
                                      "-Dtest=SessionResetTest", "-Dsurefire.failIfNoSpecifiedTests=false")
        self.assertEqual(0, result.returncode)
        self.assertEqual("-B -pl seclume-pool test -Dtest=SessionResetTest -Dsurefire.failIfNoSpecifiedTests=false",
                         calls[1])

    def test_a_failed_build_runs_no_tests_and_keeps_its_exit_code(self):
        result, calls = self.run_with("-B", "-pl", "seclume-mysql", "-am", "test", codes=(3, 0))
        self.assertEqual(3, result.returncode)
        self.assertEqual(1, len(calls))
        self.assertIn("install -DskipTests", calls[0])

    def test_failing_tests_fail_the_step(self):
        result, calls = self.run_with("-B", "-pl", "seclume-mysql", "-am", "test", codes=(0, 1))
        self.assertEqual(1, result.returncode)
        self.assertEqual(2, len(calls))

    def test_without_also_make_the_arguments_pass_as_they_are(self):
        result, calls = self.run_with("-B", "-pl", "seclume-core", "test")
        self.assertEqual(0, result.returncode)
        self.assertEqual(["-B -pl seclume-core test"], calls)

    def test_without_the_test_goal_the_arguments_pass_as_they_are(self):
        result, calls = self.run_with("-B", "-pl", "seclume-verify", "-am", "package", "-DskipTests")
        self.assertEqual(["-B -pl seclume-verify -am package -DskipTests"], calls)


if __name__ == "__main__":
    unittest.main()
