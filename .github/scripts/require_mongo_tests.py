"""Fail CI if a MongoDB test was skipped or failed: a skipped live test proves nothing.

Two exceptions: the Reactive Streams TCK's "untested_" cases, rules the TCK
itself says it cannot check, which it always reports as skipped; and the
"control" tests, which run the vendor's own client with the secret in hand to
show that the heap search would find it - they run on request only, in a step
of their own.

Other modules with live fixtures use it too: the module directory patterns
(comma-separated) and a name for the messages as arguments (by default
seclume-mongodb* and MongoDB).
"""
import pathlib
import sys
import xml.etree.ElementTree as ET


def problems(root, modules="seclume-mongodb*", label="MongoDB"):
    bad, seen = [], 0
    reports = sorted(report for pattern in modules.split(",")
                     for report in pathlib.Path(root).glob(
                         pattern.strip() + "/target/surefire-reports/TEST-*.xml"))
    for report in reports:
        for case in ET.parse(report).getroot().iter("testcase"):
            seen += 1
            name = f"{case.get('classname')}.{case.get('name')}"
            if case.find("failure") is not None or case.find("error") is not None:
                bad.append(f"failed: {name}")
            elif case.find("skipped") is not None and not case.get("name", "").startswith(
                    ("untested_", "control")):
                bad.append(f"skipped: {name}")
    if seen == 0:
        bad.append(f"no {label} test reports at all")
    return bad, seen


if __name__ == "__main__":
    modules = sys.argv[1] if len(sys.argv) > 1 else "seclume-mongodb*"
    label = sys.argv[2] if len(sys.argv) > 2 else "MongoDB"
    bad, seen = problems(".", modules, label)
    print("\n".join(bad) or f"all {seen} {label} tests ran and passed")
    sys.exit(1 if bad else 0)
