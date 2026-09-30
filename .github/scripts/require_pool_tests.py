"""Fail CI if its database's pool regressions are absent, skipped or failed."""
import sys
from pathlib import Path
# UTF-8-only reports, with DTDs/entities rejected before parsing in read_report.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml


def read_report(report):
    document = report.read_text(encoding="utf-8")
    if "\x00" in document or "<!DOCTYPE" in document.upper() or "<!ENTITY" in document.upper():
        raise ValueError(f"DTD/entity declarations are not allowed in {report}")
    return ET.fromstring(document)


def require(database, reports):
    index = {"PostgreSQL": 1, "MySQL": 2, "SQL Server": 3, "Oracle": 4}[database]
    methods = (
        "theNextBorrowerDoesNotInheritTheTenant",
        "aConnectionThatSetNothingGoesBackAsItWas",
        "statementsLeftOpenAreClosedOnReturnAndCounted",
        "hiddenProcedureStateDoesNotReachTheNextBorrower",
    )
    expected = {"SessionResetTest": [f"{method}(Db)[{index}]" for method in methods]}
    if database == "Oracle":
        expected["SessionResetTest"].append("anAlteredOracleSessionIsReplacedNotLent")
    if database == "PostgreSQL":
        expected["PoolHandOnSeamTest"] = [
            "aDetachedConnectionIsOpenAndNoLongerThePools",
            "anAdoptedConnectionIsReturnedLikeAnyOther",
            "aFullPoolRefusesToAdopt",
            "aConnectionFromElsewhereCannotBeDetached",
            "tenantAndTransactionSurviveHandoffAndAreResetOnlyOnReturn",
        ]
    errors = []
    for suite, names in expected.items():
        report = reports / f"TEST-space.seclume.pool.{suite}.xml"
        if not report.exists():
            errors.append(f"missing report: {report}")
            continue
        cases = {case.get("name"): case for case in read_report(report).iter("testcase")}
        for name in names:
            case = cases.get(name)
            if case is None:
                errors.append(f"missing test: {suite}.{name}")
            elif any(case.find(tag) is not None for tag in ("skipped", "failure", "error")):
                errors.append(f"test did not pass: {suite}.{name}")
    if errors:
        raise ValueError("\n".join(errors))
    return sum(map(len, expected.values()))


if __name__ == "__main__":
    try:
        count = require(sys.argv[1], Path("seclume-pool/target/surefire-reports"))
        print(f"{sys.argv[1]}: {count} required pool regressions executed and passed")
    except (ValueError, OSError, ET.ParseError) as error:
        sys.exit(str(error))
