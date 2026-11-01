import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

WRAPPER = Path(__file__).resolve().parent / "mvnw-retry.sh"


class MvnwRetryTest(unittest.TestCase):
    """mvnw-retry.sh against a stand-in ./mvnw whose behaviour is scripted per attempt."""

    def run_with(self, attempts):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            for i, (code, output) in enumerate(attempts, start=1):
                (work / f"attempt-{i}").write_text(f"{code}\n{output}\n")
            mvnw = work / "mvnw"
            mvnw.write_text(
                "#!/usr/bin/env bash\n"
                "n=$(( $(cat count 2>/dev/null || echo 0) + 1 )); echo $n > count\n"
                "echo \"args: $*\"\n"
                "tail -n +2 attempt-$n\n"
                "exit $(head -1 attempt-$n)\n")
            mvnw.chmod(mvnw.stat().st_mode | stat.S_IEXEC)
            result = subprocess.run(["bash", str(WRAPPER), "-B", "test"], cwd=work, capture_output=True,
                                    text=True, env={**os.environ, "MVNW_RETRY_PAUSE": "0"}, timeout=60)
            calls = int((work / "count").read_text())
            return result, calls

    def test_success_the_first_time_is_left_alone(self):
        result, calls = self.run_with([(0, "BUILD SUCCESS")])
        self.assertEqual(0, result.returncode)
        self.assertEqual(1, calls)
        self.assertIn("args: -B test", result.stdout)

    def test_a_failure_before_the_build_is_retried_and_reported(self):
        result, calls = self.run_with([(1, "Could not download the wrapper"), (0, "BUILD SUCCESS")])
        self.assertEqual(0, result.returncode)
        self.assertEqual(2, calls)
        self.assertIn("::warning title=mvnw attempt 1::exited 1", result.stdout)
        self.assertIn("Could not download the wrapper", result.stdout)

    def test_a_failure_of_the_build_itself_is_passed_on_at_once(self):
        result, calls = self.run_with([(1, "[INFO] Reactor Build Order:\n[ERROR] BUILD FAILURE"),
                                       (0, "BUILD SUCCESS")])
        self.assertEqual(1, result.returncode)
        self.assertEqual(1, calls, "a real failure is not hidden behind a second attempt")

    def test_a_failing_test_is_passed_on_at_once(self):
        result, calls = self.run_with([(1, "Tests run: 3, Failures: 1"), (0, "")])
        self.assertEqual(1, result.returncode)
        self.assertEqual(1, calls)

    def test_three_failures_before_the_build_give_up_with_the_last_code(self):
        result, calls = self.run_with([(1, "no network"), (1, "no network"), (7, "still none")])
        self.assertEqual(7, result.returncode)
        self.assertEqual(3, calls)
        self.assertEqual(3, result.stdout.count("::warning title=mvnw attempt"))


if __name__ == "__main__":
    unittest.main()
