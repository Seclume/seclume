"""Summarize a TLS-Anvil run: counts, and every test that did not succeed.

Writes Markdown to stdout (for the job summary and the PR comment) and
prints GitHub annotations for the failures. With --baseline, also compares
against the expected results and exits 1 on a regression: a test that
succeeded in the baseline and does not any more, or one that is new and fails.
"""
import glob
import json
import os
import sys

SUCCESS = {"STRICTLY_SUCCEEDED", "CONCEPTUALLY_SUCCEEDED"}


def load(folder):
    reports = glob.glob(os.path.join(folder, "**", "report.json"), recursive=True)
    if not reports:
        sys.exit("no report.json under " + folder)
    report = json.load(open(reports[0]))
    runs = {}
    for path in glob.glob(os.path.join(folder, "**", "_testRun.json"), recursive=True):
        run = json.load(open(path))
        test_id = run.get("TestId") or os.path.basename(os.path.dirname(path))
        runs[test_id] = run
    return report, runs


def main():
    folder = sys.argv[1]
    baseline_path = None
    if "--baseline" in sys.argv:
        baseline_path = sys.argv[sys.argv.index("--baseline") + 1]
    write_expected = None
    if "--write-expected" in sys.argv:
        write_expected = sys.argv[sys.argv.index("--write-expected") + 1]

    report, runs = load(folder)
    counts = {
        "Strictly succeeded": report.get("StrictlySucceededTests", 0),
        "Conceptually succeeded": report.get("ConceptuallySucceededTests", 0),
        "Partially failed": report.get("PartiallyFailedTests", 0),
        "Fully failed": report.get("FullyFailedTests", 0),
        "Disabled (not applicable)": report.get("DisabledTests", 0),
        "Test suite errors": report.get("TestSuiteErrorTests", 0),
    }
    out = ["## TLS-Anvil: seclume's TLS client", "",
           f"Strength {report.get('Strength')}, {report.get('TotalTests')} tests, "
           f"{report.get('ElapsedTime', 0) // 60000} min.", "",
           "| Result | Tests |", "|---|---|"]
    out += [f"| {name} | {count} |" for name, count in counts.items()]

    by_result = {}
    for test_id, run in runs.items():
        by_result.setdefault(run.get("Result") or "NOT_SPECIFIED", []).append(test_id)
    if write_expected:
        json.dump({k: sorted(v) for k, v in sorted(by_result.items())},
                  open(write_expected, "w"), indent=2)

    failing = [(test_id, run) for test_id, run in sorted(runs.items())
               if run.get("Result") in ("PARTIALLY_FAILED", "FULLY_FAILED", "TEST_SUITE_ERROR")]
    if failing:
        out += ["", "### Not passed", "", "| Test | Result | Class.method | Reason |",
                "|---|---|---|---|"]
        for test_id, run in failing:
            reason = (run.get("FailedReason") or "").replace("|", "\\|").replace("\n", " ")[:300]
            where = f"{(run.get('TestClass') or '').split('.')[-1]}.{run.get('TestMethod') or ''}"
            out.append(f"| {test_id} | {run.get('Result')} | {where} | {reason} |")
            print(f"::warning title=TLS-Anvil {test_id}::{run.get('Result')} {where}: "
                  f"{reason[:200]}", file=sys.stderr)

    regressions = []
    if baseline_path and os.path.exists(baseline_path):
        baseline = json.load(open(baseline_path))
        expected = {t: r for r, ids in baseline.items() for t in ids}
        for test_id, run in runs.items():
            now = run.get("Result")
            before = expected.get(test_id)
            if now in SUCCESS or now == "DISABLED":
                continue
            if before is None or before in SUCCESS:
                regressions.append((test_id, before or "new", now))
        out += ["", f"Compared with `{baseline_path}`: "
                + (f"**{len(regressions)} regression(s)**" if regressions else "no regression.")]
        for test_id, before, now in regressions:
            out.append(f"- {test_id}: {before} -> {now}")
            print(f"::error title=TLS-Anvil regression {test_id}::{before} -> {now}",
                  file=sys.stderr)

    print("\n".join(out))
    sys.exit(1 if regressions else 0)


if __name__ == "__main__":
    main()
