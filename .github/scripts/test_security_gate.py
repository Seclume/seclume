import json
import os
import tempfile
import unittest

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


def case(name, result=None):
    inner = {"skip": "<skipped/>", "fail": "<failure message='x'/>",
             "error": "<error message='x'/>"}.get(result, "")
    return f"<testcase classname='{name}' name='t'>{inner}</testcase>"


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
        with tempfile.TemporaryDirectory() as root:
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
