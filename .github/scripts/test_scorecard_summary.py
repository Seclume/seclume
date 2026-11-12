import contextlib
import io
import json
import os
import tempfile
import unittest

from scorecard_summary import annotations, main, rows, table

RESULT = {
    "date": "2026-11-11", "score": 7.4,
    "repo": {"name": "github.com/Seclume/seclume", "commit": "0123456789abcdef"},
    "scorecard": {"version": "v5"},
    "checks": [
        {"name": "Pinned-Dependencies", "score": 10, "reason": "all pinned",
         "documentation": {"url": "https://example.org/pinned"}},
        {"name": "Branch-Protection", "score": -1, "reason": "internal error: token"},
        {"name": "Code-Review", "score": 0, "reason": "Found 0/30 approved | changesets"},
        {"name": "Maintained", "score": 3, "reason": "repo was\ncreated recently"},
    ],
}


class ScorecardSummaryTest(unittest.TestCase):
    def test_lowest_first_and_not_scored_last(self):
        self.assertEqual([r[0] for r in rows(RESULT)],
                         ["Code-Review", "Maintained", "Pinned-Dependencies", "Branch-Protection"])

    def test_the_table_names_score_reason_and_link(self):
        text = table(RESULT)
        self.assertIn("### OpenSSF Scorecard: 7.4 / 10", text)
        self.assertIn("Commit 0123456789ab", text)
        self.assertIn("| [Pinned-Dependencies](https://example.org/pinned) | 10 | all pinned |", text)
        self.assertIn("| Branch-Protection | not scored | internal error: token |", text)
        self.assertIn("Found 0/30 approved / changesets", text)    # a | would break the row
        self.assertIn("| Maintained | 3 | repo was created recently |", text)

    def test_a_warning_for_each_check_below_ten(self):
        lines = annotations(RESULT)
        self.assertIn("::warning title=Scorecard Code-Review::0/10: Found 0/30 approved | changesets", lines)
        self.assertIn("::notice title=Scorecard Pinned-Dependencies::10/10: all pinned", lines)
        self.assertIn("::notice title=Scorecard Branch-Protection::not scored: internal error: token", lines)

    def test_main_reads_the_file_and_writes_the_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "results.json")
            with open(path, "w", encoding="utf-8") as out:
                json.dump(RESULT, out)
            summary = os.path.join(directory, "summary.md")
            os.environ["GITHUB_STEP_SUMMARY"] = summary
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["x", path]), 0)
            finally:
                del os.environ["GITHUB_STEP_SUMMARY"]
            with open(summary, encoding="utf-8") as written:
                self.assertIn("| Maintained | 3 |", written.read())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["x"]), 2)


if __name__ == "__main__":
    unittest.main()
