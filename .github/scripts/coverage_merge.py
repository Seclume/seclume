#!/usr/bin/env python3
"""One coverage report from the jobs that ran the tests.

The core job runs the unit tests; the drivers' integration tests run in the
database jobs, each against its own server. Each uploads its JaCoCo execution
data and the classes it was recorded against as an artifact named
coverage-exec-<job>. This merges all of them - every job's, every module's -
with JaCoCo's command line, and writes each module's report from that, where
coverage_report.py reads it:

    <module>/target/site/jacoco/jacoco.xml

    python3 .github/scripts/coverage_merge.py <artifacts> <repository> <jacococli.jar>

<artifacts> holds one directory per artifact, as actions/download-artifact
lays them out. The classes of a module are taken from the first artifact that
has them - every job compiled the same commit with the same JDK - and a class
whose recorded data does not match them is reported, not hidden: JaCoCo
counts it as not covered, and the run says how many there were.
"""

import subprocess
import sys
from pathlib import Path


def plan(artifacts):
    """{module: {"exec": [paths], "classes": path or None, "jobs": [names]}}.

    A module is in the plan when some job compiled it, whether or not its own
    tests ran there: its code may have run under another module's tests.
    """
    modules = {}
    for artifact in sorted(p for p in Path(artifacts).iterdir() if p.is_dir()):
        job = artifact.name.removeprefix("coverage-exec-")
        for classes in sorted(artifact.glob("*/target/classes")):
            module = classes.parent.parent.name
            entry = modules.setdefault(module, {"exec": [], "classes": None, "jobs": []})
            if entry["classes"] is None and classes.is_dir():
                entry["classes"] = classes
        for data in sorted(artifact.glob("*/target/jacoco.exec")):
            module = data.parent.parent.name
            entry = modules.setdefault(module, {"exec": [], "classes": None, "jobs": []})
            entry["exec"].append(data)
            entry["jobs"].append(job)
    return modules


def commands(modules, repository, cli):
    """The command lines: one merge of every job's and every module's data, then a
    report per module that has classes and sources.

    Every module's data goes into every module's report. The core's TLS client
    runs under the drivers' tests, a Vault PKI issuer under seclume-keys' - and
    each of those checks what it ran. A report of only the module's own tests
    would call that code untested.
    """
    everything = sorted({str(path) for entry in modules.values() for path in entry["exec"]})
    result = {}
    if not everything:
        return result
    merged = Path(repository) / "target" / "jacoco-all.exec"
    result[None] = [["java", "-jar", str(cli), "merge", *everything,
                     "--destfile", str(merged)]]
    for module, entry in modules.items():
        sources = Path(repository) / module / "src" / "main" / "java"
        if entry["classes"] is None or not sources.is_dir():
            continue
        site = Path(repository) / module / "target" / "site" / "jacoco"
        result[module] = [
            ["java", "-jar", str(cli), "report", str(merged),
             "--classfiles", str(entry["classes"]), "--sourcefiles", str(sources),
             "--xml", str(site / "jacoco.xml"), "--html", str(site)],
        ]
    return result


def main(arguments, run=subprocess.run):
    artifacts, repository, cli = arguments
    modules = plan(artifacts)
    mismatched = 0
    for module, steps in commands(modules, repository, cli).items():
        directory = (Path(repository) / "target" if module is None
                     else Path(repository) / module / "target" / "site" / "jacoco")
        directory.mkdir(parents=True, exist_ok=True)
        for step in steps:
            done = run(step, capture_output=True, text=True)
            output = (done.stdout or "") + (done.stderr or "")
            mismatched += output.count("does not match")
            if done.returncode != 0:
                print(f"::error title=coverage {module or 'merge'}::{' '.join(step[3:4])} "
                      f"failed: {output.strip()[:500]}")
                return 1
        if module is not None:
            own = ", ".join(modules[module]["jobs"]) or "no job"
            print(f"{module}: its own tests in {own}; every other module's tests counted too")
    if mismatched:
        print(f"::warning title=coverage::{mismatched} classes' execution data did not match "
              "their class files and count as not covered")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
