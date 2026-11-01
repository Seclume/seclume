import hashlib
import http.server
import os
import threading
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

    def test_four_failures_before_the_build_give_up_with_the_last_code(self):
        result, calls = self.run_with([(1, "no network"), (1, "no network"), (1, "no network"),
                                       (7, "still none")])
        self.assertEqual(7, result.returncode)
        self.assertEqual(4, calls)
        self.assertEqual(4, result.stdout.count("::warning title=mvnw attempt"))

    def test_a_third_failure_before_the_build_is_still_retried(self):
        result, calls = self.run_with([(1, "no network"), (1, "no network"), (1, "no network"),
                                       (0, "BUILD SUCCESS")])
        self.assertEqual(0, result.returncode)
        self.assertEqual(4, calls)

    # ---- the wrapper jar, kept in the local repository

    JAR = b"PK\x03\x04 a stand-in for maven-wrapper-3.3.3.jar"

    def workspace(self, directory, sha=None, mvnw_writes_jar=False):
        work = Path(directory) / "work"
        (work / ".mvn" / "wrapper").mkdir(parents=True)
        digest = sha or hashlib.sha256(self.JAR).hexdigest()
        (work / ".mvn" / "wrapper" / "maven-wrapper.properties").write_text(
            "distributionType=bin\r\nwrapperVersion=3.3.3\r\nwrapperSha256Sum=" + digest + "\r\n")
        mvnw = work / "mvnw"
        script = "#!/usr/bin/env bash\n"
        if mvnw_writes_jar:
            script += "printf '%s' '" + self.JAR.decode("latin-1") + "' > .mvn/wrapper/maven-wrapper.jar\n"
        script += ("if [ -s .mvn/wrapper/maven-wrapper.jar ]; then echo 'jar present'; else echo 'no jar'; fi\n"
                   "exit 0\n")
        mvnw.write_text(script)
        mvnw.chmod(mvnw.stat().st_mode | stat.S_IEXEC)
        repository = Path(directory) / "repository"
        kept = repository / "org/apache/maven/wrapper/maven-wrapper/3.3.3/maven-wrapper-3.3.3.jar"
        return work, repository, kept

    def run_in(self, work, repository, sources=None):
        env = {**os.environ, "MVNW_RETRY_PAUSE": "0", "MVNW_REPOSITORY": str(repository)}
        if sources is None:
            env["MVNW_NO_FETCH"] = "1"
        else:
            env["MVNW_JAR_SOURCES"] = " ".join(sources)
        return subprocess.run(["bash", str(WRAPPER), "-v"], cwd=work, capture_output=True, text=True,
                              env=env, timeout=60)

    def serve(self, routes):
        """A local HTTP server: path -> (status, body); everything else 404."""
        seen = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append(self.path)
                status, body = routes.get(self.path, (404, b"not here"))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *arguments):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return "http://127.0.0.1:%d" % server.server_address[1], seen

    PATH = "/org/apache/maven/wrapper/maven-wrapper/3.3.3/maven-wrapper-3.3.3.jar"

    def test_the_jar_is_fetched_from_the_mirror_when_central_fails(self):
        central, central_seen = self.serve({"/a" + self.PATH: (429, b"slow down")})
        mirror, mirror_seen = self.serve({"/b" + self.PATH: (200, self.JAR)})
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory)
            result = self.run_in(work, repository, [central + "/a", mirror + "/b"])
            self.assertTrue(1 <= len(central_seen) <= 3, central_seen)
            self.assertEqual({"/a" + self.PATH}, set(central_seen), "a 429 is retried by curl, twice at most")
            self.assertEqual(["/b" + self.PATH], mirror_seen)
            self.assertIn("the wrapper jar 3.3.3 from " + mirror + "/b", result.stdout)
            self.assertIn("jar present", result.stdout)
            self.assertEqual(self.JAR, kept.read_bytes(), "and kept for the next job")

    def test_a_fetched_jar_with_another_checksum_is_thrown_away(self):
        central, _ = self.serve({self.PATH: (200, b"something else")})
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory)
            result = self.run_in(work, repository, [central])
            self.assertIn("no jar", result.stdout)
            self.assertFalse((work / ".mvn/wrapper/maven-wrapper.jar.part").exists())
            self.assertIn("::warning title=mvnw wrapper jar::not fetched - " + central + ": 200;", result.stdout)

    def test_when_no_source_has_it_the_statuses_are_reported(self):
        central, _ = self.serve({self.PATH: (403, b"no")})
        mirror, _ = self.serve({})
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory)
            result = self.run_in(work, repository, [central, mirror])
            self.assertIn(central + ": 403;", result.stdout)
            self.assertIn(mirror + ": 404;", result.stdout)
            self.assertIn("no jar", result.stdout)

    def test_a_kept_jar_with_the_right_checksum_is_used(self):
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory)
            kept.parent.mkdir(parents=True)
            kept.write_bytes(self.JAR)
            result = self.run_in(work, repository)
            self.assertIn("the wrapper jar 3.3.3 from the local repository", result.stdout)
            self.assertIn("jar present", result.stdout)
            self.assertEqual(self.JAR, (work / ".mvn/wrapper/maven-wrapper.jar").read_bytes())

    def test_a_kept_jar_with_another_checksum_is_not_used(self):
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory, sha="0" * 64)
            kept.parent.mkdir(parents=True)
            kept.write_bytes(self.JAR)
            nowhere, _ = self.serve({})
            result = self.run_in(work, repository, [nowhere])
            self.assertNotIn("from the local repository", result.stdout)
            self.assertIn("no jar", result.stdout)

    def test_a_jar_the_wrapper_fetched_is_kept_for_the_next_job(self):
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory, mvnw_writes_jar=True)
            result = self.run_in(work, repository)
            self.assertEqual(0, result.returncode)
            self.assertEqual(self.JAR, kept.read_bytes())

    def test_a_fetched_jar_with_another_checksum_is_not_kept(self):
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory, sha="1" * 64, mvnw_writes_jar=True)
            self.run_in(work, repository)
            self.assertFalse(kept.exists())

    def test_an_existing_jar_is_left_as_it_is(self):
        with tempfile.TemporaryDirectory() as directory:
            work, repository, kept = self.workspace(directory)
            (work / ".mvn/wrapper/maven-wrapper.jar").write_bytes(b"the checked-in one")
            kept.parent.mkdir(parents=True)
            kept.write_bytes(self.JAR)
            result = self.run_in(work, repository)
            self.assertNotIn("from the local repository", result.stdout)
            self.assertEqual(b"the checked-in one", (work / ".mvn/wrapper/maven-wrapper.jar").read_bytes())


if __name__ == "__main__":
    unittest.main()
