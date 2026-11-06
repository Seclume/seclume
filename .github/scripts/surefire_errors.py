"""Failing tests as error annotations on the check: the test, the last
"Caused by:" of its stack trace and the assertion's message - read on the
pull request or the nightly run without opening the log, which this
repository's automation cannot download.

  surefire_errors.py [root]

Reads every target/surefire-reports/TEST-*.xml under root (default: .).
A failure whose message is the failure threshold surefire stops at is
skipped: the test that caused it is reported on its own.
"""
import glob
import os
import sys
# The reports are this build's own surefire output, not documents from outside.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

LIMIT = 700


def errors(root):
    """[(title, text)] for every failed or erroneous test case under root."""
    found = []
    pattern = os.path.join(root, "**", "target", "surefire-reports", "TEST-*.xml")
    for path in sorted(glob.glob(pattern, recursive=True)):
        try:
            tree = ET.parse(path)
        except ET.ParseError as e:
            found.append((os.path.relpath(path, root), f"an unreadable report: {e}"))
            continue
        for case in tree.getroot().iter("testcase"):
            for bad in case.findall("failure") + case.findall("error"):
                text = (bad.get("type") or "") + ": " + (bad.get("message") or "")
                if "failure threshold" in text:
                    continue
                causes = [line.strip() for line in (bad.text or "").splitlines()
                          if line.strip().startswith("Caused by:")]
                if causes:
                    text = causes[-1] + " | " + text
                found.append((f"{case.get('classname')}.{case.get('name')}", text))
    return found


def annotation(title, text):
    """One ::error line, in what a workflow command accepts."""
    def clean(value):
        return value.replace("%", "%25").replace("\r", " ").replace("\n", " ")
    return f"::error title={clean(title).replace(':', '%3A').replace(',', '%2C')}::{clean(text)[:LIMIT]}"


def main(root="."):
    found = errors(root)
    for title, text in found:
        print(annotation(title, text))
    print("failing tests:", len(found))


if __name__ == "__main__":
    main(*sys.argv[1:])
