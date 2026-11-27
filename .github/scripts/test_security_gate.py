import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest import mock

import security_gate

MANIFEST = {
    "platforms": ["linux-x64", "windows-x64"],
    "groups": {"g": [
        {"test": "a.Passes", "module": "m", "property": "p"},
        {"test": "a.Fails", "module": "m", "property": "p"},
        {"test": "a.Skips", "module": "m", "property": "p"},
        {"test": "a.Partly", "module": "m", "property": "p"},
        {"test": "a.Missing", "module": "m", "property": "p"},
        {"test": "a.LinuxOnly", "module": "m", "property": "p", "platforms": ["linux-x64"]},
        {"test": "a.SkipsOnWindows", "module": "m", "property": "p",
         "skips": {"windows-x64": "no /proc there"}},
    ]},
}


def case(name, result=None, method="t"):
    inner = {"skip": "<skipped/>", "fail": "<failure message='x'/>",
             "error": "<error message='x'/>"}.get(result, "")
    return f"<testcase classname='{name}' name='{method}'>{inner}</testcase>"


def reports(root, cases):
    folder = os.path.join(root, "m", "target", "surefire-reports")
    os.makedirs(folder)
    with open(os.path.join(folder, "TEST-all.xml"), "w", encoding="utf-8") as f:
        f.write("<testsuite>" + "".join(cases) + "</testsuite>")


class SecurityGateTest(unittest.TestCase):

    def statuses(self, platform, cases):
        with tempfile.TemporaryDirectory() as root:
            reports(root, cases)
            return {test: verdict for verdict, test, _, _ in
                    security_gate.evaluate(MANIFEST, "g", platform, root)}

    def test_each_outcome_gets_its_status(self):
        got = self.statuses("linux-x64", [
            case("a.Passes"), case("a.Passes"),
            case("a.Fails"), case("a.Fails", "fail"),
            case("a.Skips", "skip"),
            case("a.Partly"), case("a.Partly", "skip"),
            case("a.LinuxOnly"),
            case("a.SkipsOnWindows"), case("a.SkipsOnWindows", "skip"),
        ])
        self.assertEqual("PASS", got["a.Passes"])
        self.assertEqual("FAIL", got["a.Fails"])
        self.assertEqual("SKIPPED", got["a.Skips"])
        self.assertEqual("INCONCLUSIVE", got["a.Partly"])
        self.assertEqual("FAIL", got["a.Missing"], "a test that did not run is no pass")
        self.assertEqual("PASS", got["a.LinuxOnly"])
        self.assertEqual("INCONCLUSIVE", got["a.SkipsOnWindows"],
                         "a skip allowed on Windows is not allowed on Linux")

    def test_platforms_and_declared_skips(self):
        got = self.statuses("windows-x64", [
            case("a.SkipsOnWindows"), case("a.SkipsOnWindows", "skip"),
        ])
        self.assertEqual("NOT APPLICABLE", got["a.LinuxOnly"])
        self.assertEqual("PASS", got["a.SkipsOnWindows"])
        only_skipped = self.statuses("windows-x64", [case("a.SkipsOnWindows", "skip")])
        self.assertEqual("SKIPPED", only_skipped["a.SkipsOnWindows"],
                         "a declared skip still needs something that ran")

    def test_an_error_is_a_failure(self):
        self.assertEqual("FAIL", self.statuses("linux-x64", [case("a.Passes", "error")])
                         ["a.Passes"])

    def test_the_gate_exits_nonzero_unless_everything_passes(self):
        # Neither into the job's summary nor as an annotation on the run: the
        # failure this test makes on purpose is not the build's.
        environment = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        with mock.patch.dict(os.environ, environment, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), tempfile.TemporaryDirectory() as root:
            manifest = {"platforms": ["linux-x64"], "groups": {"g": [
                {"test": "a.Passes", "module": "m", "property": "p"}]}}
            path = os.path.join(root, "manifest.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)
            reports(root, [case("a.Passes")])
            self.assertEqual(0, security_gate.main(["--group", "g", "--root", root,
                                                    "--manifest", path]))
            manifest["groups"]["g"].append({"test": "a.Gone", "module": "m", "property": "p"})
            with open(path, "w", encoding="utf-8") as f:
                json.dump(manifest, f)
            self.assertEqual(1, security_gate.main(["--group", "g", "--root", root,
                                                    "--manifest", path]))

    # The manifest's "methods": a class is not its claim.

    def method_statuses(self, platform, entry, cases):
        manifest = {"platforms": ["linux-x64", "windows-x64"], "groups": {"g": [entry]}}
        with tempfile.TemporaryDirectory() as root:
            reports(root, cases)
            return [(verdict, note) for verdict, _, _, note in
                    security_gate.evaluate(manifest, "g", platform, root)][0]

    def test_a_placeholder_case_is_no_pass_for_the_listed_methods(self):
        entry = {"test": "a.Wipes", "module": "m", "property": "p",
                 "methods": ["wipesOnClose", "wipesOnError"]}
        verdict, note = self.method_statuses("linux-x64", entry, [case("a.Wipes", method="placeholder")])
        self.assertEqual("FAIL", verdict, "one passing case named anything used to be a PASS")
        self.assertIn("wipesOnClose", note)
        self.assertIn("wipesOnError", note)

    def test_a_parameterized_test_emptied_to_fewer_cases_fails(self):
        entry = {"test": "a.Sweep", "module": "m", "property": "p",
                 "methods": ["everyPrefix"], "min_cases": 3}
        three = [case("a.Sweep", method="everyPrefix") for _ in range(3)]
        self.assertEqual("PASS", self.method_statuses("linux-x64", entry, three)[0])
        verdict, note = self.method_statuses("linux-x64", entry, three[:1])
        self.assertEqual("FAIL", verdict, "one case left of three still passed the gate")
        self.assertIn("at least 3", note)

    def test_every_listed_method_has_to_pass(self):
        entry = {"test": "a.Wipes", "module": "m", "property": "p",
                 "methods": ["wipesOnClose", "wipesOnError"]}
        self.assertEqual("FAIL", self.method_statuses("linux-x64", entry, [
            case("a.Wipes", method="wipesOnClose")])[0], "the case that carries the property was deleted")
        self.assertEqual("FAIL", self.method_statuses("linux-x64", entry, [
            case("a.Wipes", method="wipesOnClose"), case("a.Wipes", "skip", method="wipesOnError")])[0],
            "a skip is not a pass where the manifest gives no reason for it")
        self.assertEqual("PASS", self.method_statuses("linux-x64", entry, [
            case("a.Wipes", method="wipesOnClose"), case("a.Wipes", method="wipesOnError"),
            case("a.Wipes", method="somethingNew")])[0], "a method the list does not name is not asked for")

    def test_parameters_and_repetitions_belong_to_their_method(self):
        entry = {"test": "a.Rejects", "module": "m", "property": "p", "methods": ["rejects", "again"]}
        self.assertEqual("PASS", self.method_statuses("linux-x64", entry, [
            case("a.Rejects", method="rejects(String)[1]"), case("a.Rejects", method="rejects(String)[2]"),
            case("a.Rejects", method="again()")])[0])
        self.assertEqual("FAIL", self.method_statuses("linux-x64", entry, [
            case("a.Rejects", method="rejects(String)[1]"), case("a.Rejects", "fail", method="rejects(String)[2]"),
            case("a.Rejects", method="again()")])[0], "one failed parameter fails the method")
        self.assertEqual("rejects", security_gate.method_of("rejects(String, int)[3]"))
        self.assertEqual("again", security_gate.method_of("again[1]"))

    def test_a_declared_skip_counts_a_skipped_method_as_run(self):
        entry = {"test": "a.Proc", "module": "m", "property": "p", "methods": ["reads", "limits"],
                 "skips": {"windows-x64": "no /proc there"}}
        cases = [case("a.Proc", method="reads"), case("a.Proc", "skip", method="limits")]
        self.assertEqual("PASS", self.method_statuses("windows-x64", entry, cases)[0])
        self.assertEqual("FAIL", self.method_statuses("linux-x64", entry, cases)[0])

    def test_the_gate_reads_the_manifest_it_is_given(self):
        # On a pull request the workflow passes the base branch's manifest
        # (trusted_gate.sh): the one in the checkout is not read.
        environment = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
        with mock.patch.dict(os.environ, environment, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".github"))
            relaxed = {"platforms": ["linux-x64"], "groups": {"g": [
                {"test": "a.Wipes", "module": "m", "property": "p", "methods": ["placeholder"]}]}}
            with open(os.path.join(root, ".github", "security-gate.json"), "w", encoding="utf-8") as f:
                json.dump(relaxed, f)
            base = {"platforms": ["linux-x64"], "groups": {"g": [
                {"test": "a.Wipes", "module": "m", "property": "p", "methods": ["wipesOnClose"]}]}}
            trusted = os.path.join(root, "base.json")
            with open(trusted, "w", encoding="utf-8") as f:
                json.dump(base, f)
            reports(root, [case("a.Wipes", method="placeholder")])
            self.assertEqual(0, security_gate.main(["--group", "g", "--root", root]))
            self.assertEqual(1, security_gate.main(["--group", "g", "--root", root, "--manifest", trusted]))

    def test_the_repository_manifest_lists_methods_for_every_entry(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        with open(os.path.join(root, ".github", "security-gate.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        for group, entries in manifest["groups"].items():
            for entry in entries:
                self.assertTrue(entry.get("methods"), f"{group}: {entry['test']} lists no methods")
                self.assertEqual(len(entry["methods"]), len(set(entry["methods"])), entry["test"])

    def test_entities_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "r.xml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("<!DOCTYPE x [<!ENTITY a 'b'>]><testsuite/>")
            with self.assertRaises(ValueError):
                security_gate.read_report(path)

    def test_the_repository_manifest_is_well_formed(self):
        root = os.path.join(os.path.dirname(__file__), "..", "..")
        with open(os.path.join(root, ".github", "security-gate.json"), encoding="utf-8") as f:
            manifest = json.load(f)
        for group, entries in manifest["groups"].items():
            for entry in entries:
                self.assertTrue({"test", "module", "property"} <= entry.keys(), entry)
                self.assertTrue(os.path.isdir(os.path.join(root, entry["module"])), entry)
                source = os.path.join(root, entry["module"], "src", "test", "java",
                                      *entry["test"].split(".")) + ".java"
                self.assertTrue(os.path.isfile(source), f"{group}: no {source}")
                for platform in entry.get("skips", {}):
                    self.assertIn(platform, manifest["platforms"])


if __name__ == "__main__":
    unittest.main()
