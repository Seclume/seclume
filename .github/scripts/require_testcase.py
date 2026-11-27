"""Fails unless a named test case ran and passed in a surefire XML report.

    require_testcase.py <report-glob> <testcase name>

A case passed when it is in the report and holds no <failure>, <error> or
<skipped>. What it wrote to stdout or stderr - a driver's warning, say - is
no reason to fail; a grep for a self-closed <testcase .../> took it for one.
"""
import glob
import sys
from pathlib import Path

from require_pool_tests import read_report     # refuses DTDs and entities before parsing


def passed(paths, name):
    found = False
    for path in paths:
        for case in read_report(Path(path)).iter("testcase"):
            if case.get("name") != name:
                continue
            found = True
            for bad in ("failure", "error", "skipped"):
                if case.find(bad) is not None:
                    return False, f"{name} in {path}: {bad}"
    if not found:
        return False, f"{name}: not in {', '.join(paths) or 'any report'}"
    return True, f"{name}: ran and passed"


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    paths = sorted(glob.glob(argv[1]))
    ok, text = passed(paths, argv[2])
    print(text if ok else f"::error title=required test case::{text}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
