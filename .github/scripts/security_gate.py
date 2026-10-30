#!/usr/bin/env python3
"""The security gate: did every test that carries a security claim run and pass?

    security_gate.py --group core --platform linux-x64 [--root .]
    security_gate.py --group core --tests           # the -Dtest list for Maven

Reads .github/security-gate.json and the job's surefire reports and gives
each test one status:

    PASS            ran, nothing skipped, nothing failed
    FAIL            a case failed or erred - or the test did not run at all
    SKIPPED         every case was skipped
    INCONCLUSIVE    some cases ran, some were skipped
    NOT APPLICABLE  the test is not for this platform

Only PASS and NOT APPLICABLE let the build through. A skipped security test is
never a passed one: where a test may skip cases on a platform, the manifest
names the platform and the reason, and the status is PASS with that reason in
the table - never silently. The table goes to stdout and, in GitHub Actions,
to the job summary; every other status is also an error annotation.
"""
import argparse
import glob
import json
import os
import sys
from pathlib import Path
# Surefire's own reports, read after DTDs and entities are refused (see read_report).
import xml.etree.ElementTree as ET  # nosemgrep

PASSING = ("PASS", "NOT APPLICABLE")


def read_report(path):
    document = Path(path).read_text(encoding="utf-8")
    upper = document.upper()
    if "\x00" in document or "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ValueError(f"DTD/entity declarations are not allowed in {path}")
    return ET.fromstring(document)  # nosemgrep - checked above


def outcomes(root, module):
    """Every test case of the module's reports: class -> list of 'pass' / 'skip' / 'fail'."""
    found = {}
    pattern = os.path.join(root, module, "target", "surefire-reports", "TEST-*.xml")
    for path in glob.glob(pattern):
        for case in read_report(path).iter("testcase"):
            if case.find("failure") is not None or case.find("error") is not None:
                result = "fail"
            elif case.find("skipped") is not None:
                result = "skip"
            else:
                result = "pass"
            found.setdefault(case.get("classname"), []).append(result)
    return found


def status(entry, platform, cases):
    """The status of one manifest entry, and a note that says why."""
    platforms = entry.get("platforms")
    if platforms and platform not in platforms:
        return "NOT APPLICABLE", "for " + ", ".join(platforms) + " only"
    if not cases:
        return "FAIL", "did not run"
    passed, skipped, failed = (cases.count(r) for r in ("pass", "skip", "fail"))
    counts = f"{passed} passed, {skipped} skipped, {failed} failed"
    if failed:
        return "FAIL", counts
    reason = entry.get("skips", {}).get(platform)
    if skipped and reason:
        return ("PASS", f"{counts} - {reason}") if passed else ("SKIPPED", f"{counts} - {reason}")
    if skipped and passed:
        return "INCONCLUSIVE", counts
    if skipped:
        return "SKIPPED", counts
    return "PASS", counts


def evaluate(manifest, group, platform, root):
    if platform not in manifest["platforms"]:
        raise ValueError(f"unknown platform {platform}: one of {manifest['platforms']}")
    if group not in manifest["groups"]:
        raise ValueError(f"unknown group {group}: one of {sorted(manifest['groups'])}")
    cache = {}
    rows = []
    for entry in manifest["groups"][group]:
        module = entry["module"]
        if module not in cache:
            cache[module] = outcomes(root, module)
        verdict, note = status(entry, platform, cache[module].get(entry["test"], []))
        rows.append((verdict, entry["test"], entry["property"], note))
    return rows


def table(rows, group, platform):
    lines = [f"### Security gate: {group} on {platform}", "",
             "| Status | Test | Property | Result |", "|---|---|---|---|"]
    for verdict, test, prop, note in rows:
        lines.append(f"| {verdict} | `{test.rsplit('.', 1)[-1]}` | {prop} | {note} |")
    bad = [r for r in rows if r[0] not in PASSING]
    lines += ["", f"{len(rows) - len(bad)} of {len(rows)} through"
              + ("" if not bad else f"; {len(bad)} block the build")]
    return "\n".join(lines)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--group", required=True)
    parser.add_argument("--platform", default="linux-x64")
    parser.add_argument("--root", default=".")
    parser.add_argument("--manifest", default=None)
    parser.add_argument("--tests", action="store_true",
                        help="print the group's tests as a Maven -Dtest list and stop")
    options = parser.parse_args(argv)
    manifest_path = options.manifest or os.path.join(options.root, ".github", "security-gate.json")
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    if options.tests:
        print(",".join(entry["test"] for entry in manifest["groups"][options.group]))
        return 0
    rows = evaluate(manifest, options.group, options.platform, options.root)
    report = table(rows, options.group, options.platform)
    print(report)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(report + "\n")
    bad = [r for r in rows if r[0] not in PASSING]
    for verdict, test, _, note in bad:
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::error title=security gate {verdict}::{test} on {options.platform}: {note}")
    return 1 if bad else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (ValueError, OSError, ET.ParseError, KeyError) as error:
        sys.exit(f"security gate: {error}")
