"""Fail CI if a MongoDB test was skipped or failed: a skipped live test proves nothing."""
import pathlib
import re
import sys

COUNTS = re.compile(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+), Skipped: (\d+)")


def problems(root):
    bad, seen = [], 0
    for report in sorted(pathlib.Path(root).glob("seclume-mongodb*/target/surefire-reports/*.txt")):
        match = COUNTS.search(report.read_text(encoding="utf-8"))
        if not match:
            continue
        seen += int(match.group(1))
        if any(int(match.group(i)) for i in (2, 3, 4)):
            bad.append(f"{report.name}: {match.group(0)}")
    if seen == 0:
        bad.append("no MongoDB test reports at all")
    return bad, seen


if __name__ == "__main__":
    bad, seen = problems(".")
    print("\n".join(bad) or f"all {seen} MongoDB tests ran and passed")
    sys.exit(1 if bad else 0)
