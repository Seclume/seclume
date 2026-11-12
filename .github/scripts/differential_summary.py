"""What seclume-diff ran against one database: per test class how many cases
ran, were skipped and failed - into the job summary, with the failures as
error annotations (surefire_errors.py).

A differential test without its server skips, and a skip is green: this is
where it shows which classes compared anything at all.

  differential_summary.py <server> [root]
"""
import glob
import os
import sys
# The reports are this build's own surefire output, not documents from outside.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

import surefire_errors


def classes(root):
    """{class: [ran, skipped, failed]} from seclume-diff's reports under root."""
    counts = {}
    pattern = os.path.join(root, "seclume-diff", "target", "surefire-reports", "TEST-*.xml")
    for path in sorted(glob.glob(pattern)):
        for case in ET.parse(path).getroot().iter("testcase"):
            name = (case.get("classname") or "?").rsplit(".", 1)[-1]
            row = counts.setdefault(name, [0, 0, 0])
            if case.find("skipped") is not None:
                row[1] += 1
            elif case.find("failure") is not None or case.find("error") is not None:
                row[2] += 1
            else:
                row[0] += 1
    return counts


def table(server, counts):
    """The job summary: a line of totals, then a row per class."""
    ran = sum(row[0] for row in counts.values())
    skipped = sum(row[1] for row in counts.values())
    failed = sum(row[2] for row in counts.values())
    lines = [f"### seclume-diff against {server}", "",
             f"{len(counts)} classes: {ran} passed, {failed} failed, {skipped} skipped", "",
             "| class | passed | failed | skipped |", "|---|---:|---:|---:|"]
    for name in sorted(counts):
        row = counts[name]
        lines.append(f"| {name} | {row[0]} | {row[2]} | {row[1]} |")
    return "\n".join(lines) + "\n"


def main(argv):
    if len(argv) not in (2, 3):
        print(__doc__)
        return 2
    root = argv[2] if len(argv) == 3 else "."
    summary = table(argv[1], classes(root))
    print(summary)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as out:
            out.write(summary)
    surefire_errors.main(os.path.join(root, "seclume-diff"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
