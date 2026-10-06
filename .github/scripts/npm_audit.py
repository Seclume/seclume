"""Fail CI on any npm advisory of moderate or higher severity in the CI tools,
except the ones listed in ACCEPTED - each with the reason it cannot reach us.

The CI tools are test helpers only (Azure's storage emulator); nothing from
them ships. `npm audit` itself cannot leave out a single advisory, so it is
read as JSON here instead.
"""
import json
import shutil
import subprocess
import sys

LEVELS = ("info", "low", "moderate", "high", "critical")

# Keep in step with .github/ci-tools/osv-scanner.toml, the same list for
# osv-scanner and Scorecard.
ACCEPTED = {
    # sprintf-js <= 1.1.3, no patched version. Reached only through tedious,
    # the SQL Server client of Azurite's optional SQL metadata store. The CI
    # leaves AZURITE_DB unset, so Azurite keeps its metadata in its own files
    # and tedious is never loaded.
    "https://github.com/advisories/GHSA-hp3w-g68c-fv3c",
}


def findings(report, level="moderate"):
    """The advisories at or above `level` that are not accepted."""
    floor = LEVELS.index(level)
    found = set()
    for package in report.get("vulnerabilities", {}).values():
        for via in package.get("via", []):
            # A string names another vulnerable package; its own advisory is
            # judged where that package is listed.
            if isinstance(via, dict) and LEVELS.index(via.get("severity", "critical")) >= floor:
                url = via.get("url", via.get("title", "unknown advisory"))
                if url not in ACCEPTED:
                    found.add(f"{via.get('name', '?')}: {url}")
    return sorted(found)


if __name__ == "__main__":
    audit = subprocess.run([shutil.which("npm") or "npm", "audit", "--json"], capture_output=True, text=True, check=False)
    problems = findings(json.loads(audit.stdout))
    for problem in problems:
        print(problem)
    sys.exit(1 if problems else 0)
