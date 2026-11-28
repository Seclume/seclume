#!/usr/bin/env python3
"""The lines a change adds or alters, as path:line - for pit_report.py.

    changed_lines.py BASE_SHA [PATH...] > changed-lines.txt

Read from git diff -U0 against BASE_SHA: each hunk's new side, the lines that
are there after the change. Deleted lines leave nothing to mutate.
"""
import re
import subprocess
import sys

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed(diff):
    """{path: set(line)} of a unified diff with no context."""
    found = {}
    path = None
    for line in diff.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            path = None if name == "/dev/null" else name[2:] if name.startswith("b/") else name
            continue
        match = HUNK.match(line)
        if match and path:
            start, count = int(match.group(1)), int(match.group(2) or "1")
            found.setdefault(path, set()).update(range(start, start + count))
    return found


def main(argv):
    if not argv:
        print(__doc__.splitlines()[2].strip(), file=sys.stderr)
        return 2
    diff = subprocess.run(["git", "diff", "-U0", "--no-color", argv[0], "--", *argv[1:]],
                          check=True, capture_output=True, text=True).stdout
    for path, lines in sorted(changed(diff).items()):
        for number in sorted(lines):
            print(f"{path}:{number}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
