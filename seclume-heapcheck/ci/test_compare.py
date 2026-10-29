import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from compare import compare, compare_discovery, main, read_full, read_report


DETECTORS = ["jwt", "vault-token", "url-password"]


def discovery(found, ignored=(), detectors=None):
    """A report's discovery object: found maps detector -> distinct values."""
    ran = [d for d in (detectors or DETECTORS) if d not in ignored]
    entries = []
    for detector, count in found.items():
        for value in range(1, count + 1):
            entries.append({"detector": detector, "name": detector, "value": value,
                            "occurrences": 2, "findings": []})
    return {"verdict": "FOUND" if entries else "NOT_FOUND", "detectors": ran,
            "ignored": list(ignored), "found": entries}


def write_report(path, secrets=None, found=None, ignored=()):
    data = {"tool": "seclume-heapcheck development", "secrets": []}
    leaked = False
    for source, hit in (secrets or {}).items():
        leaked = leaked or hit
        data["secrets"].append({"source": source, "kind": "text",
                                "result": "FOUND" if hit else "NOT_FOUND",
                                "findings": [{"position": 1}] if hit else []})
    data["verdict"] = "FOUND" if leaked else "NOT_FOUND"
    if found is not None:
        data["discovery"] = discovery(found, ignored)
    path.write_text(json.dumps(data), encoding="utf-8")


class CompareTest(unittest.TestCase):
    def test_changed_addresses_do_not_create_new_leaks(self):
        changes = compare({"db": ("text", True)}, {"db": ("text", True)})
        self.assertEqual(changes["persistent"], ["db"])
        self.assertEqual(changes["new"], [])

    def test_missing_or_changed_kind_is_not_a_fix(self):
        changes = compare({"db": ("text", True), "key": ("binary", True)},
                          {"key": ("text", False)})
        self.assertEqual(changes["not_checked"], ["db", "key"])
        self.assertEqual(changes["resolved"], [])

    def test_new_resolved_and_added(self):
        changes = compare({"db": ("text", True), "api": ("text", False)},
                          {"db": ("text", False), "api": ("text", True), "key": ("binary", True)})
        self.assertEqual(changes["resolved"], ["db"])
        self.assertEqual(changes["new"], ["api", "key"])
        self.assertEqual(changes["added"], ["key"])

    def test_json_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            previous, current = Path(directory) / "previous.json", Path(directory) / "current.json"
            def write(path, found):
                path.write_text(json.dumps({"tool": "seclume-heapcheck development",
                    "verdict": "FOUND" if found else "NOT_FOUND", "secrets": [
                        {"source": "db", "kind": "text", "result": "FOUND" if found else "NOT_FOUND",
                         "findings": [{"position": 19}] if found else []}]}), encoding="utf-8")
            write(previous, True)
            write(current, True)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(previous), str(current)]), 1)
                write(current, False)
                self.assertEqual(main([str(previous), str(current)]), 0)
            for invalid in ["{}", "[]", '{"tool":"x","tool":"y"}', "not JSON"]:
                current.write_text(invalid, encoding="utf-8")
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(previous), str(current)]), 2)

    def test_inconsistent_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "bad.json"
            report.write_text(json.dumps({"tool": "seclume-heapcheck development", "verdict": "NOT_FOUND",
                "secrets": [{"source": "db", "kind": "text", "result": "FOUND", "findings": []}]}))
            with self.assertRaises(ValueError):
                read_report(report)


class DiscoveryCompareTest(unittest.TestCase):
    def ran(self, found, ignored=()):
        data = discovery(found, ignored)
        return {"detectors": set(data["detectors"]), "values": dict(found)}

    def test_new_persistent_resolved_and_more_values(self):
        changes = compare_discovery(self.ran({"jwt": 1, "vault-token": 2}),
                                    self.ran({"jwt": 3, "url-password": 1}))
        self.assertEqual(changes["persistent"], ["jwt"])
        self.assertEqual(changes["more_values"], ["jwt"])
        self.assertEqual(changes["new"], ["url-password"])
        self.assertEqual(changes["resolved"], ["vault-token"])
        self.assertEqual(changes["not_checked"], [])

    def test_ignoring_a_detector_is_not_a_fix(self):
        changes = compare_discovery(self.ran({"jwt": 1}), self.ran({}, ignored=["jwt"]))
        self.assertEqual(changes["resolved"], [])
        self.assertEqual(changes["not_checked"], ["jwt"])

    def test_not_discovering_at_all_is_not_a_fix(self):
        changes = compare_discovery(self.ran({"jwt": 1}), None)
        self.assertEqual(changes["resolved"], [])
        self.assertIn("jwt", changes["not_checked"])

    def test_a_first_discovery_is_all_new(self):
        changes = compare_discovery(None, self.ran({"jwt": 1}))
        self.assertEqual(changes["new"], ["jwt"])

    def test_reports_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            previous, current = Path(directory) / "previous.json", Path(directory) / "current.json"
            out = io.StringIO()
            # A discovery-only report is a valid scope of its own.
            write_report(previous, found={"jwt": 1})
            write_report(current, found={})
            self.assertEqual(read_full(current)[1]["values"], {})
            with contextlib.redirect_stdout(out):
                self.assertEqual(main([str(previous), str(current)]), 0)
            self.assertEqual(json.loads(out.getvalue())["discovery"]["resolved"], ["jwt"])
            # A baseline never waives a finding: still there means exit 1.
            write_report(current, found={"jwt": 1})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(previous), str(current)]), 1)
            # Ignoring the detector does not make it go away.
            write_report(current, found={}, ignored=["jwt"])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(previous), str(current)]), 1)
            # Named secrets and discovery together: both have to be clean.
            write_report(previous, secrets={"db": False}, found={})
            write_report(current, secrets={"db": False}, found={"vault-token": 1})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(previous), str(current)]), 1)
            write_report(current, secrets={"db": False}, found={})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(previous), str(current)]), 0)

    def test_an_inconsistent_discovery_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "bad.json"
            for broken in [
                    {**discovery({"jwt": 1}), "verdict": "NOT_FOUND"},
                    {**discovery({}), "found": [{"detector": "unknown", "value": 1, "occurrences": 1}]},
                    {**discovery({}), "found": [{"detector": "jwt", "value": 0, "occurrences": 1}]},
                    {**discovery({}), "detectors": "jwt"}]:
                report.write_text(json.dumps({"tool": "seclume-heapcheck development",
                    "verdict": "NOT_FOUND", "secrets": [], "discovery": broken}))
                with self.assertRaises(ValueError):
                    read_full(report)
            # Without discovery, an empty scope is still no report.
            report.write_text(json.dumps({"tool": "seclume-heapcheck development",
                "verdict": "NOT_FOUND", "secrets": []}))
            with self.assertRaises(ValueError):
                read_full(report)


if __name__ == "__main__":
    unittest.main()
