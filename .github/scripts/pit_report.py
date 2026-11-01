"""PIT's verdict for one package, as annotations on the check.

  pit_report.py <mutations.xml> <source root> <package>

A notice with the score: of the mutants with a test that ran their line,
how many a test noticed - and how many had no test that ran them at all.
Then the survivors as warnings, grouped by class: line, mutator, method
and what PIT changed. A check takes ten warnings per step, so classes are
packed into at most ten annotations, the classes with most survivors first;
each names its file and its first surviving line.

Exits 0: the annotations are the result, not a gate.
"""
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
        })
    return mutations


def score(mutations):
    """(killed, covered, no coverage, total): covered excludes NO_COVERAGE."""
    killed = sum(1 for m in mutations if m["status"] in ("KILLED", "TIMED_OUT", "MEMORY_ERROR"))
    uncovered = sum(1 for m in mutations if m["status"] == "NO_COVERAGE")
    return killed, len(mutations) - uncovered, uncovered, len(mutations)


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


def main(report, source_root, package):
    if not Path(report).exists():
        print(f"::error title=mutation ({package})::no PIT report at {report} - the run did not finish")
        return
    mutations = read(report)
    killed, covered, uncovered, total = score(mutations)
    percent = 100.0 * killed / covered if covered else 0.0
    print(f"::notice title=mutation ({package})::{killed} of {covered} mutants with a test killed "
          f"({percent:.1f}%), {covered - killed} survived; {uncovered} of {total} on lines no test ran")
    for path, line, title, text in annotations(survivors_by_class(mutations), source_root):
        print(f"::warning file={path},line={line},title={escape(title)}::{escape(text)}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3])
