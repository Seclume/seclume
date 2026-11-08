#!/usr/bin/env python3
"""Line and branch coverage from JaCoCo's reports, module by module.

Reads every <module>/target/site/jacoco/jacoco.xml under the repository,
and writes:

  - a Markdown table per module and one for the security-critical packages
    (.github/coverage-critical.json names them) - to stdout, and to the job
    summary when GITHUB_STEP_SUMMARY is set;
  - coverage.json with the same numbers, the commit and the run they came
    from - the source of what SECURITY-QUALITY.md publishes.

Counted, never estimated: a module without a report is listed as such, not
as zero and not left out.

    python3 .github/scripts/coverage_report.py [repository] [--json coverage.json]
"""

import json
import os
import sys
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml
from pathlib import Path


def counters(element):
    """{'LINE': (missed, covered), 'BRANCH': (...)} of an element's own counters."""
    result = {}
    for counter in element.findall("counter"):
        result[counter.get("type")] = (int(counter.get("missed")), int(counter.get("covered")))
    return result


def ratio(pair):
    missed, covered = pair
    total = missed + covered
    return None if total == 0 else covered / total


def read_report(path):
    """The module's totals and its packages' totals from one jacoco.xml."""
    # JaCoCo's report names a DTD; nothing is fetched or resolved here.
    root = ET.parse(path).getroot()
    packages = {}
    for package in root.findall("package"):
        name = package.get("name").replace("/", ".")
        packages[name] = counters(package)
    return counters(root), packages


def collect(repository):
    modules = {}
    for pom in sorted(Path(repository).glob("*/pom.xml")):
        module = pom.parent.name
        report = pom.parent / "target" / "site" / "jacoco" / "jacoco.xml"
        if not (pom.parent / "src" / "main" / "java").is_dir():
            continue
        if report.is_file():
            totals, packages = read_report(report)
            modules[module] = {"totals": totals, "packages": packages}
        else:
            modules[module] = None
    return modules


def critical_packages(modules, critical):
    """Each critical package prefix summed over the modules that have it."""
    result = {}
    for entry in critical:
        prefix = entry["package"]
        line = [0, 0]
        branch = [0, 0]
        found = False
        for data in modules.values():
            if not data:
                continue
            for name, numbers in data["packages"].items():
                if name == prefix or name.startswith(prefix + "."):
                    found = True
                    for kind, target in (("LINE", line), ("BRANCH", branch)):
                        missed, covered = numbers.get(kind, (0, 0))
                        target[0] += missed
                        target[1] += covered
        result[prefix] = {"why": entry["why"], "found": found,
                          "LINE": tuple(line), "BRANCH": tuple(branch)}
    return result


def total(modules):
    """LINE and BRANCH summed over every module that has a report."""
    sums = {"LINE": [0, 0], "BRANCH": [0, 0]}
    for data in modules.values():
        if not data:
            continue
        for kind, target in sums.items():
            missed, covered = data["totals"].get(kind, (0, 0))
            target[0] += missed
            target[1] += covered
    return {kind: tuple(pair) for kind, pair in sums.items()}


def counted(pair):
    """'covered / all' - the counts themselves, so that a percentage can be checked."""
    missed, covered = pair
    return f"{covered} / {missed + covered}"


def percent(pair):
    value = ratio(pair) if pair else None
    return "-" if value is None else f"{value * 100:.1f} %"


def markdown(modules, critical):
    lines = ["## Coverage (JaCoCo)", "",
             "| Module | Lines covered | Line coverage | Branches covered | Branch coverage |",
             "|---|---:|---:|---:|---:|"]
    for module, data in modules.items():
        if data is None:
            lines.append(f"| {module} | - | no report | - | - |")
            continue
        line = data["totals"].get("LINE", (0, 0))
        branch = data["totals"].get("BRANCH", (0, 0))
        lines.append(f"| {module} | {counted(line)} | {percent(line)} | {counted(branch)} | "
                     f"{percent(branch)} |")
    whole = total(modules)
    lines.append(f"| **all modules with a report** | {counted(whole['LINE'])} | "
                 f"{percent(whole['LINE'])} | {counted(whole['BRANCH'])} | "
                 f"{percent(whole['BRANCH'])} |")
    lines += ["", "### Security-critical packages", "",
              "| Package | Why | Lines covered | Line coverage | Branches covered | Branch coverage |",
              "|---|---|---:|---:|---:|---:|"]
    for name, data in critical.items():
        if not data["found"]:
            lines.append(f"| `{name}` | {data['why']} | - | no report | - | - |")
            continue
        lines.append(f"| `{name}` | {data['why']} | {counted(data['LINE'])} | "
                     f"{percent(data['LINE'])} | {counted(data['BRANCH'])} | "
                     f"{percent(data['BRANCH'])} |")
    return "\n".join(lines) + "\n"


def as_json(modules, critical):
    def numbers(totals):
        return {kind.lower(): {"missed": totals.get(kind, (0, 0))[0],
                               "covered": totals.get(kind, (0, 0))[1]}
                for kind in ("LINE", "BRANCH")}
    return {
        "commit": os.environ.get("GITHUB_SHA"),
        "run": (f"{os.environ['GITHUB_SERVER_URL']}/{os.environ['GITHUB_REPOSITORY']}"
                f"/actions/runs/{os.environ['GITHUB_RUN_ID']}")
        if os.environ.get("GITHUB_RUN_ID") else None,
        "modules": {module: (numbers(data["totals"]) if data else None)
                    for module, data in modules.items()},
        "total": numbers(total(modules)),
        "critical": {name: {"why": data["why"], **(numbers(data) if data["found"] else {})}
                     for name, data in critical.items()},
    }


def main(arguments):
    repository = "."
    output = None
    rest = list(arguments)
    if "--json" in rest:
        at = rest.index("--json")
        output = rest[at + 1]
        del rest[at:at + 2]
    if rest:
        repository = rest[0]
    with open(Path(repository) / ".github" / "coverage-critical.json", encoding="utf-8") as f:
        critical_list = json.load(f)
    modules = collect(repository)
    critical = critical_packages(modules, critical_list)
    text = markdown(modules, critical)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(text)
    if output:
        with open(output, "w", encoding="utf-8") as f:
            json.dump(as_json(modules, critical), f, indent=2, sort_keys=True)
            f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
