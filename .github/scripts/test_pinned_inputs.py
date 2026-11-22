import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import pinned_inputs

DIGEST = "@sha256:" + "ab" * 32


def write(root, relative, text):
    path = os.path.join(root, *relative.split("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


WORKFLOW = """jobs:
  db:
    services:
      postgres:
        image: postgres:18
      pinned:
        image: mysql:8.4""" + DIGEST + """
      matrix:
        image: ${{ matrix.image }}
    steps:
      - run: |
          docker run -d --name oracle --network host \\
            -e ORACLE_PASSWORD="$pw" -p 1521:1521 \\
            gvenzl/oracle-free:23-slim
          docker run -d --name bouncer -v "$PWD/b:/etc/b" edoburu/pgbouncer""" + DIGEST + """   # 1.26
          # docker run commented/out:1 is no input
          docker build -t local-tool:ci .
          docker run --rm local-tool:ci
          image=cockroachdb/cockroach:v26.2.11
          docker run -d "$image"
          bash kind_load.sh seclume docker.io/library/eclipse-temurin:25-jdk
          curl -fsSL -o "$zip" "https://example.org/dist/$zip"
          curl -fsSL "https://example.org/dist/$zip.sha256"
"""

SCRIPT = """#!/usr/bin/env bash
image=${MONGO_IMAGE:-docker.io/library/mongo:8.0}
balancer=docker.io/library/haproxy:3.4""" + DIGEST + """
"""

DOCKERFILE = "FROM eclipse-temurin:25-jre" + DIGEST + "\nFROM scratch\n"


class PinnedInputsTest(unittest.TestCase):

    def tree(self, root, wrapper_sum=False):
        write(root, ".github/workflows/ci.yml", WORKFLOW)
        write(root, ".github/scripts/fixtures.sh", SCRIPT)
        write(root, "module/Dockerfile", DOCKERFILE)
        write(root, ".mvn/wrapper/maven-wrapper.properties",
              "distributionUrl=https://repo.example/apache-maven-3.10.0-bin.zip\n"
              + ("distributionSha256Sum=" + "cd" * 32 + "\n" if wrapper_sum else ""))

    def found(self, root):
        return [what for _, what in pinned_inputs.unpinned(root)]

    def test_every_kind_of_unpinned_input_is_found(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            found = self.found(root)
            for expected in ("postgres:18", "${{matrix.image}}", "gvenzl/oracle-free:23-slim",
                             "cockroachdb/cockroach:v26.2.11", "docker.io/library/eclipse-temurin:25-jdk",
                             "docker.io/library/mongo:8.0"):
                self.assertIn(expected, found)
            self.assertTrue(any("example.org/dist/$zip" in f and "same server" in f for f in found), found)
            self.assertTrue(any("apache-maven-3.10.0" in f for f in found), found)

    def test_pinned_built_and_commented_inputs_are_not(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root, wrapper_sum=True)
            found = self.found(root)
            for absent in ("mysql:8.4", "edoburu/pgbouncer", "local-tool:ci", "commented/out:1",
                           "docker.io/library/haproxy:3.4", "eclipse-temurin:25-jre", "scratch"):
                self.assertFalse(any(f.startswith(absent) for f in found), (absent, found))
            self.assertFalse(any("apache-maven" in f for f in found), "the wrapper's sum pins it")

    def check(self, root, entries):
        write(root, pinned_inputs.RATCHET, json.dumps({"unpinned": entries}))
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = pinned_inputs.main(["--check", "--root", root])
        return code, out.getvalue()

    def test_the_ratchet_only_shrinks(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root)
            everything = [{"file": f, "input": i} for f, i in pinned_inputs.unpinned(root)]
            self.assertEqual(0, self.check(root, everything)[0])
            code, out = self.check(root, everything[1:])
            self.assertEqual(1, code, "an unpinned input the list does not name")
            self.assertIn("not pinned: " + everything[0]["file"], out)
            code, out = self.check(root, everything + [{"file": "x.yml", "input": "gone:1"}])
            self.assertEqual(1, code, "a listed input that is no longer unpinned stays listed")
            self.assertIn("take it off", out)

    def test_pinning_puts_the_digest_after_each_tag_once(self):
        with tempfile.TemporaryDirectory() as root:
            self.tree(root, wrapper_sum=True)
            with mock.patch.object(pinned_inputs, "digest", return_value="sha256:" + "ef" * 32) as asked, \
                    contextlib.redirect_stdout(io.StringIO()):
                pinned_inputs.main(["--pin", "--root", root])
                pinned_inputs.main(["--pin", "--root", root])
            with open(os.path.join(root, ".github", "workflows", "ci.yml"), encoding="utf-8") as f:
                text = f.read()
            self.assertIn("image: postgres:18@sha256:" + "ef" * 32 + "\n", text)
            self.assertIn("gvenzl/oracle-free:23-slim@sha256:" + "ef" * 32 + "\n", text)
            self.assertNotIn("@sha256:" + "ef" * 32 + "@", text, "pinned twice")
            self.assertIn("image: ${{ matrix.image }}", text, "a matrix value is pinned in the matrix")
            self.assertNotIn("local-tool:ci@", text)
            left = self.found(root)
            self.assertIn("${{matrix.image}}", left)
            self.assertNotIn("postgres:18", left)
            self.assertNotIn(mock.call("local-tool:ci"), asked.call_args_list)

    def test_the_repository_has_no_input_its_ratchet_does_not_list(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        new, done = pinned_inputs.check(root)
        self.assertEqual([], new)
        self.assertEqual([], done)


if __name__ == "__main__":
    unittest.main()
