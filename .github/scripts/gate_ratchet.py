#!/usr/bin/env python3
"""The security gate and the coverage floors only get stricter, unless a change says why.

    gate_ratchet.py --base BASE_SHA        (in CI: the pull request's base commit)
    gate_ratchet.py --base-gate F --base-floors F [--gate F --floors F]

The gate itself is taken from the base branch (trusted_gate.sh), so a pull
request that relaxes it is still judged by the old one. Once merged, though,
the relaxation holds. This makes it visible where it is made: each weakening
- a test or a method taken out of the manifest, a min_cases lowered, a new
skip or a narrower list of platforms, a coverage floor lowered or removed -
fails the build unless the new file names it, word for word, in its
"relaxed" list with a reason:

    "relaxed": [{"what": "<the line this script prints>", "why": "..."}]

That list is in the diff a code owner reviews, next to the change it explains.
"""
import argparse
import json
import subprocess
import sys

GATE = ".github/security-gate.json"
FLOORS = ".github/coverage-floors.json"


def at(commit, path):
    return json.loads(subprocess.run(["git", "show", commit + ":" + path], check=True,
                                     capture_output=True, text=True).stdout)


def read(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def entries(gate):
    found = {}
    for group, tests in gate.get("groups", {}).items():
        for entry in tests:
            found[(group, entry["test"])] = entry
    return found


def gate_weakenings(base, head):
    weaker = []
    now = entries(head)
    for key, before in sorted(entries(base).items()):
        group, test = key
        after = now.get(key)
        if after is None:
            weaker.append(f"gate: {group} {test} removed")
            continue
        for method in before.get("methods", []):
            if method not in after.get("methods", []):
                weaker.append(f"gate: {group} {test} method {method} removed")
        if after.get("min_cases", 0) < before.get("min_cases", 0):
            weaker.append(f"gate: {group} {test} min_cases {before['min_cases']} -> "
                          f"{after.get('min_cases', 0)}")
        for platform, reason in after.get("skips", {}).items():
            if platform not in before.get("skips", {}):
                weaker.append(f"gate: {group} {test} may skip on {platform}")
        was, now_on = before.get("platforms"), after.get("platforms")
        if now_on and (not was or set(now_on) < set(was)):
            weaker.append(f"gate: {group} {test} only on {', '.join(sorted(now_on))}")
    for platform in base.get("platforms", []):
        if platform not in head.get("platforms", []):
            weaker.append(f"gate: platform {platform} removed")
    return weaker


def floor_weakenings(base, head):
    weaker = []
    for scope in ("total", "modules", "packages"):
        before, after = base.get(scope, {}), head.get(scope, {})
        items = before.items() if scope != "total" else [("total", before)]
        for name, floors in items:
            now = after.get(name) if scope != "total" else after
            for kind, value in floors.items():
                if not isinstance(value, (int, float)):
                    continue
                if now is None or kind not in now:
                    weaker.append(f"floor: {scope} {name} {kind} removed")
                elif now[kind] < value:
                    weaker.append(f"floor: {scope} {name} {kind} {value} -> {now[kind]}")
    return weaker


def unexplained(weaker, *heads):
    said = {r.get("what") for head in heads for r in head.get("relaxed", [])
            if isinstance(r, dict) and str(r.get("why", "")).strip()}
    return [w for w in weaker if w not in said]


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base")
    parser.add_argument("--base-gate")
    parser.add_argument("--base-floors")
    parser.add_argument("--gate", default=GATE)
    parser.add_argument("--floors", default=FLOORS)
    options = parser.parse_args(argv)
    if options.base:
        base_gate, base_floors = at(options.base, GATE), at(options.base, FLOORS)
    elif options.base_gate and options.base_floors:
        base_gate, base_floors = read(options.base_gate), read(options.base_floors)
    else:
        parser.error("--base, or --base-gate and --base-floors")
    head_gate, head_floors = read(options.gate), read(options.floors)
    weaker = gate_weakenings(base_gate, head_gate) + floor_weakenings(base_floors, head_floors)
    left = unexplained(weaker, head_gate, head_floors)
    for line in weaker:
        print(("relaxed, said why: " if line not in left else "relaxed, not said why: ") + line)
    for line in left:
        print(f"::error title=gate ratchet::{line} - name it in the file's \"relaxed\" list "
              "with a reason, or keep it")
    if not weaker:
        print("the gate and the floors are as strict as on the base branch, or stricter")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
