import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest

import gate_methods

HERE = os.path.dirname(os.path.abspath(__file__))


def write(root, relative, text):
    path = os.path.join(root, *relative.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


TEST = """package a;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WipesTest {

    @Test
    void wipesOnClose() {}

    @ParameterizedTest(name = "{0} (case)")
    @ValueSource(strings = {"a", "b"})
    void rejects(String value) {}

    @Test @Timeout(value = 5, unit = TimeUnit.SECONDS)
    public void withTimeout() throws Exception {}

    // @Test void commentedOut() - a comment is no method, but this is a known limit

    void helper() {}

    @org.junit.jupiter.api.RepeatedTest(3)
    void repeated() {}
}
"""

CONTRACT = """package t;

import org.junit.jupiter.api.Test;

public abstract class ColumnContract {
    @Test
    void roundTrips() {}

    protected abstract Object database();
}
"""

LOCAL = """package b;

import t.ColumnContract;

class LocalColumnTest extends ColumnContract {
    @Override
    protected Object database() { return null; }
}
"""


class GateMethodsTest(unittest.TestCase):

    def tree(self, root):
        write(root, "m/src/test/java/a/WipesTest.java", TEST)
        write(root, "tck/src/main/java/t/ColumnContract.java", CONTRACT)
        write(root, "n/src/test/java/b/LocalColumnTest.java", LOCAL)
        manifest = {"platforms": ["linux-x64"], "groups": {"g": [
            {"test": "a.WipesTest", "module": "m", "property": "p"},
            {"test": "b.LocalColumnTest", "module": "n", "property": "p"}]}}
        write(root, ".github/security-gate.json", json.dumps(manifest))

    def run_main(self, *argv):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = gate_methods.main(list(argv))
        return code, out.getvalue()

    def manifest(self, root):
        with open(os.path.join(root, ".github", "security-gate.json"), encoding="utf-8") as f:
            return json.load(f)

    def test_the_methods_of_a_class_and_of_what_it_extends(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            self.assertEqual(1, self.run_main("--check", "--root", root)[0], "nothing is listed yet")
            self.assertEqual(0, self.run_main("--write", "--root", root)[0])
            entries = self.manifest(root)["groups"]["g"]
            self.assertEqual(["wipesOnClose", "rejects", "withTimeout", "repeated"], entries[0]["methods"])
            self.assertEqual(["roundTrips"], entries[1]["methods"], "inherited from another module")
            self.assertEqual(0, self.run_main("--check", "--root", root)[0])

    def test_a_listed_method_that_is_gone_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            self.run_main("--write", "--root", root)
            write(root, "m/src/test/java/a/WipesTest.java", TEST.replace("void wipesOnClose", "void renamed"))
            code, out = self.run_main("--check", "--root", root)
            self.assertEqual(1, code)
            self.assertIn("listed but not in the source: wipesOnClose", out)

    def test_a_new_method_is_reported_not_failed(self):
        # A method leaves the gate by a change to the list merged before the
        # one that deletes it; in between the source has it and the list not.
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            self.run_main("--write", "--root", root)
            manifest = self.manifest(root)
            manifest["groups"]["g"][0]["methods"].remove("repeated")
            write(root, ".github/security-gate.json", json.dumps(manifest))
            code, out = self.run_main("--check", "--root", root)
            self.assertEqual(0, code)
            self.assertIn("warning: a.WipesTest: in the source but not listed: repeated", out)

    def test_writing_keeps_the_manifest_layout_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            layout = ('{\n  "platforms": ["linux-x64"],\n  "groups": {\n    "g": [\n'
                      '      {"test": "a.WipesTest", "module": "m",\n       "property": "p {x}"},\n'
                      '      {"test": "b.LocalColumnTest", "module": "n",\n       "property": "q"}\n'
                      '    ]\n  }\n}\n')
            write(root, ".github/security-gate.json", layout)
            self.run_main("--write", "--root", root)
            with open(os.path.join(root, ".github", "security-gate.json"), encoding="utf-8") as f:
                once = f.read()
            self.assertIn('       "property": "p {x}",\n       "methods": ["wipesOnClose", ', once)
            self.assertTrue(once.startswith('{\n  "platforms": ["linux-x64"],\n'), once)
            self.run_main("--write", "--root", root)
            with open(os.path.join(root, ".github", "security-gate.json"), encoding="utf-8") as f:
                self.assertEqual(once, f.read())

    def test_the_repository_manifest_matches_the_sources(self):
        root = os.path.join(HERE, "..", "..")
        errors = [(test, why) for test, level, why in
                  gate_methods.differences(self.manifest(root), root) if level == "error"]
        self.assertEqual([], errors)


@unittest.skipUnless(shutil.which("git") and shutil.which("bash"), "needs git and bash")
class TrustedGateTest(unittest.TestCase):
    """trusted_gate.sh against a small repository standing in for the pull request's checkout."""

    def git(self, cwd, *args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                               *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()

    def test_the_base_manifest_and_script_are_used(self):
        with tempfile.TemporaryDirectory() as top:
            origin, work, temp = (os.path.join(top, n) for n in ("origin", "work", "temp"))
            os.makedirs(temp)
            os.makedirs(origin)
            self.git(origin, "init", "-q", "-b", "main")
            write(origin, ".github/security-gate.json", '{"base": true}')
            write(origin, ".github/scripts/security_gate.py", "# base\n")
            self.git(origin, "add", "-A")
            self.git(origin, "commit", "-qm", "base")
            base = self.git(origin, "rev-parse", "HEAD")
            self.git(origin, "config", "uploadpack.allowReachableSHA1InWant", "true")
            self.git(top, "clone", "-q", "file://" + origin, work)
            write(work, ".github/security-gate.json", '{"relaxed": true}')
            self.git(work, "commit", "-qam", "relax the gate")
            env_file = os.path.join(top, "env")
            environment = dict(os.environ, GITHUB_EVENT_NAME="pull_request", BASE_SHA=base,
                               RUNNER_TEMP=temp, GITHUB_ENV=env_file)
            result = subprocess.run(["bash", os.path.join(HERE, "trusted_gate.sh")], cwd=work,
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("changes the security gate", result.stdout)
            with open(env_file, encoding="utf-8") as f:
                exported = dict(line.strip().split("=", 1) for line in f if line.strip())
            with open(exported["SECURITY_GATE_MANIFEST"], encoding="utf-8") as f:
                self.assertEqual('{"base": true}', f.read())
            with open(exported["SECURITY_GATE"], encoding="utf-8") as f:
                self.assertEqual("# base\n", f.read())

    def test_outside_a_pull_request_nothing_changes(self):
        with tempfile.TemporaryDirectory() as top:
            env_file = os.path.join(top, "env")
            environment = dict(os.environ, GITHUB_EVENT_NAME="push", BASE_SHA="",
                               RUNNER_TEMP=top, GITHUB_ENV=env_file)
            result = subprocess.run(["bash", os.path.join(HERE, "trusted_gate.sh")], cwd=top,
                                    env=environment, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertFalse(os.path.exists(env_file))


if __name__ == "__main__":
    unittest.main()
