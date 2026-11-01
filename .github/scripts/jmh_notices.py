"""JMH results as notices on the check: each benchmark, seclume beside the
vendor, with the ratio - readable on the pull request or the nightly run
without downloading the artefact.

  jmh_notices.py <jmh.json> <title>

A benchmark's parameters are split into the one that names the driver or
pool (its values "seclume" and anything else) and the rest; each line pairs
seclume with the other value for the same rest. Lower is better for
AverageTime, higher for Throughput.
"""
import json
import sys
from collections import defaultdict

DRIVER_PARAMS = ("driver", "pool")


def rows(results):
    """[(benchmark, rest, side, score, error, unit, mode)] from JMH's JSON."""
    found = []
    for result in results:
        params = dict(result.get("params") or {})
        side = next((params.pop(p) for p in DRIVER_PARAMS if p in params), "")
        rest = ", ".join(f"{k}={v}" for k, v in sorted(params.items()))
        metric = result["primaryMetric"]
        found.append((result["benchmark"].rsplit(".", 2)[-2] + "." + result["benchmark"].rsplit(".", 1)[-1],
                      rest, side, metric["score"], metric.get("scoreError") or 0.0, metric["scoreUnit"],
                      result.get("mode", "avgt")))
    return found


def lines(found):
    """One line per benchmark and rest: seclume, the other side, the ratio."""
    grouped = defaultdict(dict)
    meta = {}
    for benchmark, rest, side, score, error, unit, mode in found:
        grouped[(benchmark, rest)][side] = (score, error)
        meta[(benchmark, rest)] = (unit, mode)
    out = []
    for key in sorted(grouped):
        sides = grouped[key]
        unit, mode = meta[key]
        label = key[0] + (f" [{key[1]}]" if key[1] else "")
        parts = [f"{side or 'run'} {score:.3f} ± {error:.3f} {unit}" for side, (score, error) in sorted(
            sides.items(), key=lambda item: (item[0] != "seclume", item[0]))]
        others = [s for s in sides if s and s != "seclume"]
        if "seclume" in sides and len(others) == 1 and sides[others[0]][0]:
            ours, theirs = sides["seclume"][0], sides[others[0]][0]
            ratio = ours / theirs
            better = ratio < 1 if mode in ("avgt", "sample", "ss") else ratio > 1
            parts.append(f"ratio {ratio:.2f} ({'seclume ahead' if better else 'seclume behind'})")
        out.append(f"{label}: " + " | ".join(parts))
    return out


def main(path, title):
    with open(path, encoding="utf-8") as handle:
        results = json.load(handle)
    for line in lines(rows(results)):
        print(f"::notice title={title}::{line.replace('%', '%25')}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
