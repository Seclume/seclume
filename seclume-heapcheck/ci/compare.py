#!/usr/bin/env python3
"""Compare two heapcheck JSON reports, never accepting a baseline as a waiver.

Exit 0: current scan clean and same scope; 1: current leaks or incomplete scope;
2: unreadable/invalid report. Uses source names and kinds, never secret hashes.

Named secrets are compared by source file. Discovered ones (--discover) are
compared by detector: their value numbers are counted per report and mean
nothing across two of them, so what is compared is whether a detector found
something, and how many distinct values.
"""
import argparse
import json
from pathlib import Path
import sys


def _load(path):
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
    return data


def _scope(data, allow_empty):
    secrets = data.get("secrets")
    if not isinstance(secrets, list) or (not secrets and not allow_empty):
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


def _discovery(data):
    """None when --discover did not run; else the detectors run and the distinct values each found."""
    discovery = data.get("discovery")
    if discovery is None:
        return None
    if not isinstance(discovery, dict):
        raise ValueError("invalid discovery")
    detectors, ignored, found = discovery.get("detectors"), discovery.get("ignored"), discovery.get("found")
    if (not isinstance(detectors, list) or not all(isinstance(d, str) and d for d in detectors)
            or not isinstance(ignored, list) or not all(isinstance(d, str) and d for d in ignored)
            or not isinstance(found, list)):
        raise ValueError("invalid discovery")
    values = {}
    for entry in found:
        if not isinstance(entry, dict):
            raise ValueError("invalid discovery result")
        detector, value, occurrences = entry.get("detector"), entry.get("value"), entry.get("occurrences")
        if (detector not in detectors or type(value) is not int or value < 1
                or type(occurrences) is not int or occurrences < 1):
            raise ValueError("invalid discovery result")
        values[detector] = values.get(detector, 0) + 1
    if discovery.get("verdict") != ("FOUND" if values else "NOT_FOUND"):
        raise ValueError("inconsistent discovery verdict")
    return {"detectors": set(detectors), "values": values}


def read_report(path):
    """The named secrets of a report that has some."""
    return _scope(_load(path), allow_empty=False)


def read_full(path):
    """Named secrets and discovery; a report needs at least one of the two."""
    data = _load(path)
    discovery = _discovery(data)
    return _scope(data, allow_empty=discovery is not None), discovery


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


def compare_discovery(previous, current):
    """By detector. A detector not run now - not asked for, or ignored - is not a fix."""
    changes = {key: [] for key in ("new", "persistent", "resolved", "not_checked", "more_values")}
    before_ran = previous["detectors"] if previous else set()
    before = previous["values"] if previous else {}
    now_ran = current["detectors"] if current else set()
    now = current["values"] if current else {}
    for detector, count in now.items():
        if detector in before:
            changes["persistent"].append(detector)
            if count > before[detector]:
                changes["more_values"].append(detector)
        else:
            changes["new"].append(detector)
    for detector in before:
        if detector not in now_ran:
            changes["not_checked"].append(detector)
        elif detector not in now:
            changes["resolved"].append(detector)
    for detector in before_ran - now_ran:
        if detector not in before and detector not in changes["not_checked"]:
            changes["not_checked"].append(detector)
    return {key: sorted(values) for key, values in changes.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous")
    parser.add_argument("current")
    args = parser.parse_args(argv)
    try:
        (previous, previous_discovery) = read_full(args.previous)
        (current, current_discovery) = read_full(args.current)
        changes = compare(previous, current)
        discovered = None
        if previous_discovery is not None or current_discovery is not None:
            discovered = compare_discovery(previous_discovery, current_discovery)
            changes["discovery"] = discovered
    except (OSError, ValueError, TypeError, RecursionError):
        # Report contents and decoder exceptions can contain data; do not echo them.
        print("Cannot compare: expected two valid heapcheck JSON reports.", file=sys.stderr)
        return 2
    print(json.dumps(changes, ensure_ascii=True, indent=2))
    leaks = any(found for _, found in current.values())
    leaks = leaks or bool(current_discovery and current_discovery["values"])
    incomplete = bool(changes["not_checked"]) or bool(discovered and discovered["not_checked"])
    return int(leaks or incomplete)


if __name__ == "__main__":
    sys.exit(main())
