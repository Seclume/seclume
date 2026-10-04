import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from compare import compare, main, read_report


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


if __name__ == "__main__":
    unittest.main()
