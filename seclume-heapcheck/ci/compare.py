#!/usr/bin/env python3
"""Compare two heapcheck JSON reports, never accepting a baseline as a waiver.

Exit 0: current scan clean and same scope; 1: current leaks or incomplete scope;
2: unreadable/invalid report. Uses source names and kinds, never secret hashes.
"""
import argparse
import json
from pathlib import Path
import sys


def read_report(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result

    data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(data, dict) or not isinstance(data.get("tool"), str) or not data["tool"].startswith("seclume-heapcheck "):
        raise ValueError("not a heapcheck report")
    secrets = data.get("secrets")
    if not isinstance(secrets, list) or not secrets:
        raise ValueError("missing scan scope")
    scope = {}
    for entry in secrets:
        if not isinstance(entry, dict):
            raise ValueError("invalid secret result")
        source, kind, result = entry.get("source"), entry.get("kind"), entry.get("result")
        if not isinstance(source, str) or not source or kind not in ("text", "binary") or result not in ("FOUND", "NOT_FOUND"):
            raise ValueError("invalid secret result")
        if source in scope:
            raise ValueError("duplicate source")
        findings = entry.get("findings")
        if not isinstance(findings, list) or bool(findings) != (result == "FOUND"):
            raise ValueError("inconsistent findings")
        scope[source] = (kind, result == "FOUND")
    found = any(value[1] for value in scope.values())
    if data.get("verdict") != ("FOUND" if found else "NOT_FOUND"):
        raise ValueError("inconsistent verdict")
    return scope


def compare(previous, current):
    changes = {key: [] for key in ("new", "persistent", "resolved", "not_checked", "added")}
    for source, (kind, found) in current.items():
        before = previous.get(source)
        comparable = before is not None and before[0] == kind
        if not comparable:
            changes["added"].append(source)
        if found:
            changes["persistent" if comparable and before[1] else "new"].append(source)
        elif comparable and before[1]:
            changes["resolved"].append(source)
    for source, (kind, _) in previous.items():
        if source not in current or current[source][0] != kind:
            changes["not_checked"].append(source)
    return {key: sorted(values) for key, values in changes.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous")
    parser.add_argument("current")
    args = parser.parse_args(argv)
    try:
        previous, current = read_report(args.previous), read_report(args.current)
        changes = compare(previous, current)
    except (OSError, ValueError, TypeError, RecursionError):
        # Report contents and decoder exceptions can contain data; do not echo them.
        print("Cannot compare: expected two valid heapcheck JSON reports.", file=sys.stderr)
        return 2
    print(json.dumps(changes, ensure_ascii=True, indent=2))
    return int(any(found for _, found in current.values()) or bool(changes["not_checked"]))


if __name__ == "__main__":
    sys.exit(main())
