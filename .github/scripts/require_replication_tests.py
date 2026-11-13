"""Fail CI if the read/write split's tests against real replicas are absent, skipped or failed."""
import sys
from pathlib import Path
# UTF-8-only reports, with DTDs/entities rejected before parsing in read_report.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

SUITES = ("ReadWriteSplitTest", "ReadWriteSplitMySqlTest")


def read_report(report):
    document = report.read_text(encoding="utf-8")
    if "\x00" in document or "<!DOCTYPE" in document.upper() or "<!ENTITY" in document.upper():
        raise ValueError(f"DTD/entity declarations are not allowed in {report}")
    return ET.fromstring(document)


def problems(reports):
    """What is wrong with the suites' reports under ``reports``; empty when all ran and passed."""
    errors = []
    for suite in SUITES:
        report = reports / f"TEST-space.seclume.pool.{suite}.xml"
        if not report.exists():
            errors.append(f"missing report: {report}")
            continue
        cases = list(read_report(report).iter("testcase"))
        if not cases:
            errors.append(f"{suite}: no test ran")
        for case in cases:
            for outcome in ("skipped", "failure", "error"):
                if case.find(outcome) is not None:
                    errors.append(f"{suite}.{case.get('name')}: {outcome}")
    return errors


def main(arguments):
    reports = Path(arguments[0]) if arguments else Path("seclume-pool/target/surefire-reports")
    errors = problems(reports)
    for error in errors:
        print(f"::error::{error}")
    if not errors:
        print("the read/write split ran against a PostgreSQL standby and a MySQL replica")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
