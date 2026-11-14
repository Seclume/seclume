#!/usr/bin/env python3
"""Holds the merged coverage to its floors, module by module.

    coverage_gate.py <coverage-merged.json> <coverage-floors.json>

The first file is what coverage_report.py writes with --json; the second
names, for the whole, for each module and for each security-critical
package, the line and branch coverage in whole percent it must not fall
below. Every check is one row of a table (stdout, and the job summary when
GITHUB_STEP_SUMMARY is set); every failure is also an error annotation
titled with its module or package, so that a red check says where.

Fails (exit 1) when
  - a percentage is below its floor;
  - a module or package with a floor has no measurement - a module whose
    tests stopped recording is not "no regression";
  - the floors file names a module or a package the report does not know
    at all - a renamed module would otherwise drop out of the gate unseen.

A module with a report and no floor is a warning: a new module gets its
floor from its first measurement, in the same pull request or the next.
Where a measurement is two points or more above its floor, a notice says
the floor can be raised - the floors only ever move up.
"""

import json
import math
import os
import sys


def percent(numbers):
    """Covered share in percent, or None when there is nothing to cover."""
    if not numbers:
        return None
    total = numbers["missed"] + numbers["covered"]
    return None if total == 0 else 100.0 * numbers["covered"] / total


def checks(report, floors):
    """[(scope, name, kind, measured or None, floor, verdict)] for every floor."""
    rows = []

    def check(scope, name, measured, floor):
        for kind in ("line", "branch"):
            if kind not in floor:
                continue
            value = percent((measured or {}).get(kind)) if measured is not None else None
            if measured is None:
                verdict = "no measurement"
            elif value is None:
                verdict = "nothing to cover"
            elif value < floor[kind]:
                verdict = "below"
            else:
                verdict = "ok"
            rows.append((scope, name, kind, value, floor[kind], verdict))

    if "total" in floors:
        check("total", "all modules with a report", report.get("total"), floors["total"])
    modules = report.get("modules", {})
    for name, floor in sorted(floors.get("modules", {}).items()):
        if name not in modules:
            rows.append(("module", name, "-", None, None, "unknown"))
            continue
        check("module", name, modules[name], floor)
    packages = report.get("critical", {})
    for name, floor in sorted(floors.get("packages", {}).items()):
        if name not in packages:
            rows.append(("package", name, "-", None, None, "unknown"))
            continue
        measured = packages[name]
        has_numbers = "line" in measured or "branch" in measured
        check("package", name, measured if has_numbers else None, floor)
    return rows


def without_floor(report, floors):
    """Modules with a measurement and no floor."""
    floored = floors.get("modules", {})
    return sorted(name for name, numbers in report.get("modules", {}).items()
                  if numbers is not None and name not in floored)


def failed(row):
    return row[5] in ("below", "no measurement", "unknown")


def shown(value):
    return "-" if value is None else f"{value:.1f} %"


def table(rows, spare):
    lines = ["## Coverage floors", "",
             "| Scope | Name | Kind | Measured | Floor | |", "|---|---|---|---:|---:|---|"]
    for scope, name, kind, value, floor, verdict in rows:
        mark = "FAIL" if failed((scope, name, kind, value, floor, verdict)) else verdict
        lines.append(f"| {scope} | `{name}` | {kind} | {shown(value)} | "
                     f"{'-' if floor is None else f'{floor} %'} | {mark} |")
    if spare:
        lines += ["", "Modules measured without a floor: " + ", ".join(f"`{m}`" for m in spare)]
    return "\n".join(lines) + "\n"


def annotations(rows, spare):
    out = []
    for scope, name, kind, value, floor, verdict in rows:
        if verdict == "below":
            out.append(f"::error title=coverage ({name})::{name}: {kind} coverage {shown(value)} "
                       f"is below its floor of {floor} % (.github/coverage-floors.json)")
        elif verdict == "no measurement":
            out.append(f"::error title=coverage ({name})::{name} has a {kind} floor of {floor} % "
                       f"and no coverage was measured - did its tests run?")
        elif verdict == "unknown":
            out.append(f"::error title=coverage ({name})::{name} is in .github/coverage-floors.json "
                       f"but not in the report - renamed or removed? Move or remove its floor.")
        elif verdict == "ok" and value is not None and math.floor(value) - 1 >= floor + 2:
            out.append(f"::notice title=coverage ({name})::{name}: {kind} coverage {shown(value)}, "
                       f"floor {floor} % - it can be raised to {math.floor(value) - 1} %")
    for name in spare:
        out.append(f"::warning title=coverage ({name})::{name} is measured and has no floor in "
                   f".github/coverage-floors.json yet")
    return out


def main(arguments):
    if len(arguments) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(arguments[0], encoding="utf-8") as f:
        report = json.load(f)
    with open(arguments[1], encoding="utf-8") as f:
        floors = json.load(f)
    rows = checks(report, floors)
    spare = without_floor(report, floors)
    text = table(rows, spare)
    print(text)
    for line in annotations(rows, spare):
        print(line)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    failures = [row for row in rows if failed(row)]
    if failures:
        print(f"{len(failures)} coverage check(s) failed: "
              + ", ".join(sorted({row[1] for row in failures})), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
