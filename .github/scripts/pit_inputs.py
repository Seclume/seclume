"""Whether a pull request changed anything a module's mutation result depends on.

  pit_inputs.py <base commit> <module>

A package's mutants and the tests that run against them come from the
module's sources and tests, from the seclume modules it depends on - their
sources and their tests' helpers alike - and from the build: the POMs, the
Maven configuration, the mutation workflow and its scripts. When none of that
differs from <base commit>, the pull request runs the same mutants against
the same tests as main, and cannot change their result.

Prints "changed" or "unchanged", and the files that decided it. Run in a
checkout with the base commit present (fetch-depth 0).
"""
import re
import subprocess
import sys
from pathlib import Path

BUILD = ("pom.xml", ".mvn/", ".github/workflows/mutation.yml", ".github/scripts/pit_")


def dependencies(module, root=Path(".")):
    """The module and every seclume module it depends on, transitively."""
    seen, todo = set(), [module]
    while todo:
        current = todo.pop()
        if current in seen:
            continue
        seen.add(current)
        pom = root / current / "pom.xml"
        if not pom.is_file():
            raise FileNotFoundError(f"{pom}: no such module")
        text = re.sub(r"<parent>.*?</parent>", "", pom.read_text(encoding="utf-8"), flags=re.S)
        for block in re.findall(r"<dependency>(.*?)</dependency>", text, flags=re.S):
            group = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", block)
            artifact = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", block)
            if artifact and (group is None or group.group(1) in ("space.seclume", "${project.groupId}")):
                name = artifact.group(1)
                if (root / name / "pom.xml").is_file():
                    todo.append(name)
    return sorted(seen)


def relevant(path, modules):
    return path.startswith(BUILD) or path.endswith("/pom.xml") or any(
        path.startswith(module + "/") for module in modules)


def main(base, module):
    modules = dependencies(module)
    files = subprocess.run(["git", "diff", "--name-only", f"{base}...HEAD"], check=True,
                           capture_output=True, text=True).stdout.split()
    deciding = [path for path in files if relevant(path, modules)]
    print("changed" if deciding else "unchanged")
    print(f"inputs: {', '.join(modules)} and the build", file=sys.stderr)
    for path in deciding[:20]:
        print(f"  {path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
