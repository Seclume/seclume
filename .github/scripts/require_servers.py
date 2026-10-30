"""Fail CI if a test skipped itself because it did not find the job's own server.

A test that cannot reach its database skips, and a skipped test is green. That
is right on a developer's machine without the server and wrong in the job that
started it: there, "no MySQL on 127.0.0.1:3307" means the test looked in the
wrong place, and for months nobody notices. Eighteen of the MySQL driver's
tests did exactly that.

Skips for fixtures a job does not start (a second TLS server, PostgreSQL 17,
Oracle's native encryption) are not this script's business: only the reasons
that say the job's own server, or its password file, was not found.

usage: require_servers.py <server> <module glob>[,<module glob>...]
       server: postgresql, mysql, sqlserver, oracle
"""
import pathlib
import sys
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

# What the tests say when the job's server or its password file is missing.
NOT_FOUND = {
    "postgresql": ("no PostgreSQL on ", "no PostgreSQL password file", "no .local-pg-password"),
    "mysql": ("no MySQL on ", "no MySQL password file", "no MySQL host configured",
              "no .local-mysql-password"),
    "sqlserver": ("no SQL Server on ", "no SQL Server host configured", "no .local-mssql-password"),
    "oracle": ("no Oracle on ", "no Oracle host configured", "no Oracle listener on ",
               "no .local-oracle-password"),
}


def skipped_for_want_of(server, root, modules):
    """Every test case of the modules' reports that skipped because the server was not found."""
    reasons = NOT_FOUND[server]
    found = []
    for pattern in modules.split(","):
        for report in sorted(pathlib.Path(root).glob(
                pattern.strip() + "/target/surefire-reports/TEST-*.xml")):
            for case in ET.parse(report).getroot().iter("testcase"):
                skipped = case.find("skipped")
                if skipped is None:
                    continue
                said = (skipped.get("message") or "") + " " + (skipped.text or "")
                if any(reason in said for reason in reasons):
                    found.append((f"{case.get('classname')}.{case.get('name')}",
                                  " ".join(said.split())[:200]))
    return found


def main(argv):
    if len(argv) != 3 or argv[1] not in NOT_FOUND:
        print(__doc__)
        return 2
    found = skipped_for_want_of(argv[1], ".", argv[2])
    for name, said in found:
        print(f"::error title=skipped without its server::{name}: {said}")
    if found:
        print(f"{len(found)} test(s) skipped because they did not find this job's {argv[1]}")
        return 1
    print(f"no test skipped for want of this job's {argv[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
