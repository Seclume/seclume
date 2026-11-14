"""PIT's verdict for one package, as annotations on the check.

  pit_report.py <mutations.xml>[,<mutations.xml>...] <source root> <package> [floor]

Several reports, comma-separated, are the shards of one package: their
mutants are scored together.

A notice with the score: of the mutants with a test that ran their line,
how many a test noticed - and how many had no test that ran them at all.
Then the survivors as warnings, grouped by class: line, mutator, method
and what PIT changed. A check takes ten warnings per step, so classes are
packed into at most ten annotations, the classes with most survivors first;
each names its file and its first surviving line.

Exits 0: the annotations are the result - unless a floor is given, a
percentage the score of the mutants with a test must not fall below. A floor
is the score a package had when it was set, rounded down and less a point for
the variation between runs: it keeps a change from losing what the tests
already notice, and is raised as they notice more.
"""
import re
import sys
from collections import defaultdict
from pathlib import Path
# The report is this build's own PIT output, not a document from outside.
import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml.use-defused-xml

MAX_ANNOTATIONS = 10
MAX_CHARS = 3500


def read(report):
    """[{status, class, file, method, line, mutator, description}] from mutations.xml."""
    text = Path(report).read_text(encoding="utf-8")
    if "<!DOCTYPE" in text or "<!ENTITY" in text:
        raise ValueError(f"{report}: a DTD or entity has no place in a PIT report")
    mutations = []
    for node in ET.fromstring(text).iter("mutation"):
        def field(name):
            element = node.find(name)
            return element.text.strip() if element is not None and element.text else ""
        mutations.append({
            "status": node.get("status", ""),
            "class": field("mutatedClass"),
            "file": field("sourceFile"),
            "method": field("mutatedMethod"),
            "line": int(field("lineNumber") or 0),
            "mutator": field("mutator").rsplit(".", 1)[-1],
            "description": field("description"),
            "tests_run": int(node.get("numberOfTestsRun", "0") or 0),
            "killing_test": field("killingTest"),
        })
    return mutations


def score(mutations):
    """(killed, covered, no coverage, total): covered excludes NO_COVERAGE."""
    killed = sum(1 for m in mutations if m["status"] in ("KILLED", "TIMED_OUT", "MEMORY_ERROR"))
    uncovered = sum(1 for m in mutations if m["status"] == "NO_COVERAGE")
    return killed, len(mutations) - uncovered, uncovered, len(mutations)


def test_name(killing_test):
    """class#method of a PIT test id such as '...[class:a.B]/[method:c()]', else the id itself."""
    found = dict(re.findall(r"\[(class|method|test-template):([^\]]*)\]", killing_test))
    if "class" not in found:
        return killing_test
    method = found.get("method") or found.get("test-template") or ""
    return found["class"].rsplit(".", 1)[-1] + ("#" + method.split("(", 1)[0] if method else "")


def survivors_by_class(mutations):
    """{class: [mutation]} of the survivors, each list by line."""
    grouped = defaultdict(list)
    for m in mutations:
        if m["status"] == "SURVIVED":
            grouped[m["class"]].append(m)
    for found in grouped.values():
        found.sort(key=lambda m: (m["line"], m["mutator"]))
    return dict(sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0])))


def source_path(source_root, mutation):
    package = mutation["class"].rsplit(".", 1)[0].replace(".", "/")
    return f"{source_root.rstrip('/')}/{package}/{mutation['file']}"


def annotations(grouped, source_root):
    """At most MAX_ANNOTATIONS (file, line, title, text): classes packed in order, the rest named."""
    packed = []
    hidden = []
    for name, found in grouped.items():
        short = name.rsplit(".", 1)[-1]
        text = f"{short} ({len(found)}): " + " | ".join(
            f"{m['line']} {m['method']}: {m['mutator']} - {m['description']}" for m in found)
        if packed and len(packed[-1][3]) + len(text) + 4 <= MAX_CHARS:
            packed[-1][2].append(short)
            packed[-1][3] += " || " + text
        elif len(packed) < MAX_ANNOTATIONS:
            packed.append([source_path(source_root, found[0]), found[0]["line"], [short], text[:MAX_CHARS]])
        else:
            hidden.append(f"{short} ({len(found)})")
    if hidden:
        packed[-1][3] = (packed[-1][3] + " || not shown: " + ", ".join(hidden))[:MAX_CHARS]
    result = []
    for path, line, names, text in packed:
        title = ", ".join(names[:3]) + (f" +{len(names) - 3}" if len(names) > 3 else "")
        result.append((path, line, f"survivors: {title}", text))
    return result


def escape(text):
    return text.replace("%", "%25").replace("\r", "").replace("\n", " ")


def main(report, source_root, package, floor=None):
    mutations = []
    for one in report.split(","):
        if not Path(one).exists():
            print(f"::error title=mutation ({package})::no PIT report at {one} - the run did not finish")
            return 1
        mutations += read(one)
    killed, covered, uncovered, total = score(mutations)
    percent = 100.0 * killed / covered if covered else 0.0
    overall = 100.0 * killed / total if total else 0.0
    print(f"::notice title=mutation ({package})::{killed} of {covered} mutants with a test killed "
          f"({percent:.1f}%), {covered - killed} survived; {uncovered} of {total} on lines no test ran"
          f" - {killed} of all {total} killed ({overall:.1f}%)")
    grouped = survivors_by_class(mutations)
    for path, line, title, text in annotations(grouped, source_root):
        print(f"::warning file={path},line={line},title={escape(title)}::{escape(text)}")
    # The annotations are capped; the log holds every survivor, one per line,
    # so that the work of killing them can start from the run alone.
    survivors = sum(len(found) for found in grouped.values())
    if survivors:
        print(f"::group::every survivor in {package} ({survivors})")
        for found in grouped.values():
            for m in found:
                print(f"survivor {source_path(source_root, m)}:{m['line']} {m['method']} "
                      f"{m['mutator']}: {m['description']} [{m['tests_run']} tests ran]")
        print("::endgroup::")
    # A timeout counts as killed, and whether a mutant times out can depend
    # on the runner more than on the tests: a slow one times a socket test
    # out that a fast one lets finish. The log names each one and the test
    # that ran out of time, so that the mutants a score owes to a slow runner
    # can be found and given a test that fails rather than one that waits.
    timeouts = [m for m in mutations if m["status"] == "TIMED_OUT"]
    if timeouts:
        print(f"::group::every timeout in {package} ({len(timeouts)})")
        for m in sorted(timeouts, key=lambda m: (m["class"], m["line"], m["mutator"])):
            print(f"timeout {source_path(source_root, m)}:{m['line']} {m['method']} "
                  f"{m['mutator']}: {m['description']} - in {test_name(m['killing_test']) or 'no test named'}")
        print("::endgroup::")
    if floor is not None and percent < floor:
        print(f"::error title=mutation ({package})::the score of the mutants with a test is "
              f"{percent:.1f}%, below the floor of {floor:g}% - a test stopped noticing a fault "
              "it noticed before, or new code came without one")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], sys.argv[3],
                  float(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4] else None))
