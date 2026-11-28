#!/usr/bin/env python3
"""The test methods behind each security-gate entry, kept in the manifest.

    gate_methods.py --write [--root .]     fill in every entry's "methods"
    gate_methods.py --check [--root .]     fail if the manifest and the sources disagree

The gate (security_gate.py) lets an entry through only when each method listed
here passed. The list is written from the test sources, so that what a
security test claims is what the gate asks for - and --check, run in CI, keeps
the two in step: a listed method has to exist, and one added to a gated test
but not listed is reported. On a pull request the gate reads the manifest from
the base branch (trusted_gate.sh), so a method or a test leaves the gate only
by a change to the list, merged on its own before the change that deletes it.
"""
import argparse
import json
import os
import re
import sys

ANNOTATIONS = ("Test", "ParameterizedTest", "RepeatedTest")
# An annotation line, then (after other annotations and modifiers) the method name.
METHOD = re.compile(
    r"@(?:org\.junit\.jupiter\.(?:api|params)\.)?(" + "|".join(ANNOTATIONS) + r")\b"
    r"(?:\s*\([^)]*\))?"                      # @ParameterizedTest(name = "...")
    r"(?:\s*@[\w.]+(?:\s*\((?:[^()]|\([^()]*\))*\))?)*"   # further annotations
    r"\s*(?:(?:public|protected|private|static|final|synchronized)\s+)*"
    r"(?:<[^>]*>\s*)?[\w.<>\[\], ?]+\s+(\w+)\s*\(", re.S)


def source_of(root, entry):
    path = os.path.join(root, entry["module"], "src", "test", "java",
                        *entry["test"].split(".")) + ".java"
    with open(path, encoding="utf-8") as f:
        return f.read()


EXTENDS = re.compile(r"\bclass\s+\w+(?:<[^>]*>)?\s+extends\s+([\w.]+)")
PACKAGE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)


def superclass_source(root, source):
    """The source of the class this one extends, found in any module, or None."""
    match = EXTENDS.search(source)
    if not match:
        return None
    name = match.group(1)
    if "." not in name:
        imported = re.search(r"^\s*import\s+([\w.]+\." + re.escape(name) + r")\s*;", source, re.M)
        package = PACKAGE.search(source)
        name = imported.group(1) if imported else (package.group(1) + "." + name if package else name)
    relative = os.path.join(*name.split(".")) + ".java"
    for module in sorted(os.listdir(root)):
        for kind in ("test", "main"):
            path = os.path.join(root, module, "src", kind, "java", relative)
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as f:
                    return f.read()
    return None


def all_methods(root, entry):
    """The test methods of an entry's class and of the classes it extends."""
    source = source_of(root, entry)
    names = methods_in(source)
    seen = 0
    while seen < 8:
        source = superclass_source(root, source)
        if source is None:
            break
        names += [m for m in methods_in(source) if m not in names]
        seen += 1
    return names


NOISE = re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|//[^\n]*|/\*[\s\S]*?\*/')


def code_only(source):
    """The source with its comments and the contents of its literals taken out."""
    return NOISE.sub(lambda m: '""' if m.group(0)[0] in "\"'" else " ", source)


def methods_in(source):
    """The names of the test methods in one class's source, in order, each once."""
    names = []
    for match in METHOD.finditer(code_only(source)):
        if match.group(2) not in names:
            names.append(match.group(2))
    return names


def differences(manifest, root):
    """(test, what is wrong) for every entry whose list does not match its source."""
    wrong = []
    for group, entries in manifest["groups"].items():
        for entry in entries:
            try:
                found = all_methods(root, entry)
            except OSError as e:
                wrong.append((entry["test"], "error", f"no source: {e.filename}"))
                continue
            listed = entry.get("methods")
            if listed is None:
                wrong.append((entry["test"], "error", "no methods listed"))
                continue
            gone = [m for m in listed if m not in found]
            new = [m for m in found if m not in listed]
            if gone:
                wrong.append((entry["test"], "error",
                              "listed but not in the source: " + ", ".join(gone)))
            if new:
                # Not gated yet: a method is added to the gate by listing it,
                # and taken out of it by a change to the list alone, merged
                # before the change that deletes the method.
                wrong.append((entry["test"], "warning",
                              "in the source but not listed: " + ", ".join(new)))
    return wrong


def write(manifest, root):
    for entries in manifest["groups"].values():
        for entry in entries:
            entry["methods"] = all_methods(root, entry)
    return manifest


def object_end(text, start):
    """The index just past the JSON object that opens at text[start]."""
    depth, quoted, escaped = 0, False, False
    for at in range(start, len(text)):
        c = text[at]
        if quoted:
            escaped, quoted = (not escaped and c == "\\"), (quoted if escaped or c != '"' else False)
            continue
        if c == '"':
            quoted = True
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
            if depth == 0:
                return at + 1
    raise ValueError("unbalanced manifest")


def methods_line(methods, indent, width=100):
    """'"methods": [...]', wrapped under its bracket so the file stays readable."""
    lead = indent + '"methods": ['
    lines, line = [], lead
    for i, name in enumerate(methods):
        item = json.dumps(name) + ("," if i < len(methods) - 1 else "]")
        if line != lead and len(line) + 1 + len(item) > width:
            lines.append(line)
            line = " " * len(lead) + item
        else:
            line += ("" if line == lead else " ") + item
    lines.append(line if methods else lead + "]")
    return "\n".join(lines)


def with_methods(text, manifest):
    """The manifest's text with each entry's "methods" set, its own layout kept."""
    for entries in manifest["groups"].values():
        for entry in entries:
            head = re.search(r'\{\s*"test":\s*' + re.escape(json.dumps(entry["test"])) +
                             r'\s*,\s*"module":\s*' + re.escape(json.dumps(entry["module"])), text)
            if head is None:
                raise ValueError(f"cannot find {entry['test']} in the manifest's text")
            end = object_end(text, head.start())
            body = text[head.start():end]
            indent = " " * (head.start() - text.rfind("\n", 0, head.start()) - 1 + 1)
            line = methods_line(entry["methods"], indent)
            existing = re.search(r',\s*"methods":\s*\[[^\]]*\]', body)
            if existing:
                body = body[:existing.start()] + ",\n" + line + body[existing.end():]
            else:
                body = body[:-1].rstrip() + ",\n" + line + "}"
            text = text[:head.start()] + body + text[end:]
    return text


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true")
    mode.add_argument("--check", action="store_true")
    options = parser.parse_args(argv)
    path = os.path.join(options.root, ".github", "security-gate.json")
    with open(path, encoding="utf-8") as f:
        manifest = json.load(f)
    if options.write:
        with open(path, encoding="utf-8") as f:
            text = f.read()
        write(manifest, options.root)
        text = with_methods(text, manifest)
        if json.loads(text) != manifest:
            raise SystemExit("gate_methods: the rewritten manifest does not read back the same")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return 0
    wrong = differences(manifest, options.root)
    for test, level, why in wrong:
        print(f"{level}: {test}: {why}")
        if os.environ.get("GITHUB_ACTIONS"):
            print(f"::{level} title=security gate manifest::{test}: {why}")
    return 1 if any(level == "error" for _, level, _ in wrong) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
