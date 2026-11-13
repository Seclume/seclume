import contextlib
import io
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from pit_inputs import dependencies, main, relevant


def pom(artifact, *dependencies_):
    deps = "".join(f"<dependency><groupId>space.seclume</groupId><artifactId>{d}</artifactId></dependency>"
                   for d in dependencies_)
    return (f"<project><parent><artifactId>seclume</artifactId></parent><artifactId>{artifact}</artifactId>"
            f"<dependencies>{deps}<dependency><groupId>org.junit.jupiter</groupId>"
            f"<artifactId>junit-jupiter</artifactId></dependency></dependencies></project>")


class PitInputsTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        for name, deps in {"seclume-core": (), "seclume-tck": ("seclume-core",),
                           "seclume-postgresql": ("seclume-core", "seclume-tck"),
                           "seclume-pool": ("seclume-postgresql",), "seclume-mongodb": ("seclume-core",)}.items():
            (self.root / name).mkdir()
            (self.root / name / "pom.xml").write_text(pom(name, *deps))

    def test_a_module_depends_on_what_its_dependencies_depend_on(self):
        self.assertEqual(["seclume-core", "seclume-pool", "seclume-postgresql", "seclume-tck"],
                         dependencies("seclume-pool", self.root))
        self.assertEqual(["seclume-core"], dependencies("seclume-core", self.root))

    def test_the_build_and_every_module_on_the_way_are_inputs(self):
        modules = ["seclume-core", "seclume-pool"]
        for path in ("seclume-core/src/main/java/space/seclume/tls/A.java", "seclume-core/src/test/java/T.java",
                     "seclume-pool/pom.xml", "pom.xml", ".mvn/maven.config", ".github/workflows/mutation.yml",
                     ".github/scripts/pit_report.py", "seclume-mongodb/pom.xml"):
            self.assertTrue(relevant(path, modules), path)
        for path in ("seclume-mongodb/src/main/java/M.java", "README.md", ".github/workflows/ci.yml",
                     "seclume-core-extra/A.java"):
            self.assertFalse(relevant(path, modules), path)

    def test_a_pull_request_that_left_the_inputs_alone_says_unchanged(self):
        def git(*arguments):
            subprocess.run(["git", *arguments], cwd=self.root, check=True, capture_output=True)
        git("init", "-q")
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.root, check=True, capture_output=True,
                              text=True).stdout.strip()
        (self.root / "seclume-mongodb" / "M.java").write_text("class M {}")
        git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
        git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "mongo")
        here = os.getcwd()
        os.chdir(self.root)
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                main(base, "seclume-pool")
            self.assertEqual("unchanged", output.getvalue().strip())
            (self.root / "seclume-core" / "C.java").write_text("class C {}")
            git("-c", "user.email=t@t", "-c", "user.name=t", "add", ".")
            git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "core")
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                main(base, "seclume-pool")
            self.assertEqual("changed", output.getvalue().strip())
        finally:
            os.chdir(here)


if __name__ == "__main__":
    unittest.main()
