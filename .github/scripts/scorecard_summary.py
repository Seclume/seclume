"""OpenSSF Scorecard's JSON result as something to read: every check with its
score and reason - into the job summary, and into the log as one line each
(a notice, or a warning below 10), so that the checks still open are seen on
the run and not only in the Security tab.

  scorecard_summary.py <results.json>

Scorecard says -1 where it could not decide - Branch-Protection without an
administrator's token, for one; those are listed as "not scored".
"""
import json
import os
import sys


def rows(result):
    """[(name, score, reason, url)] in Scorecard's order, lowest score first."""
    checks = []
    for check in result.get("checks", []):
        checks.append((check.get("name", "?"), check.get("score", -1),
                       " ".join((check.get("reason") or "").split()),
                       (check.get("documentation") or {}).get("url", "")))
    return sorted(checks, key=lambda c: (c[1] if c[1] >= 0 else 11, c[0]))


def table(result):
    """The job summary: the overall score, then a row per check."""
    commit = ((result.get("repo") or {}).get("commit") or "")[:12]
    lines = [f"### OpenSSF Scorecard: {result.get('score', '?')} / 10", "",
             f"Commit {commit}, {result.get('date', '?')}, Scorecard "
             f"{(result.get('scorecard') or {}).get('version', '?')}", "",
             "| check | score | reason |", "|---|---:|---|"]
    for name, score, reason, url in rows(result):
        shown = "not scored" if score < 0 else str(score)
        label = f"[{name}]({url})" if url else name
        lines.append(f"| {label} | {shown} | {reason.replace('|', '/')} |")
    return "\n".join(lines) + "\n"


def annotations(result):
    """One workflow command per check: a warning for each below 10."""
    out = []
    for name, score, reason, _ in rows(result):
        level = "notice" if score == 10 or score < 0 else "warning"
        shown = "not scored" if score < 0 else f"{score}/10"
        text = f"{shown}: {reason}".replace("%", "%25").replace("\n", " ")
        out.append(f"::{level} title=Scorecard {name}::{text}")
    return out


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    with open(argv[1], encoding="utf-8") as source:
        result = json.load(source)
    summary = table(result)
    print(summary)
    for line in annotations(result):
        print(line)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a", encoding="utf-8") as out:
            out.write(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
