"""The flake hunt's verdict: which jobs failed in some of the repeated CI runs
and passed in others, and which failed in all of them.

  summarize_flakes.py <owner/repo> <run id>

Reads the run's jobs with `gh api` - the reusable CI shows up as
"run <n> / <job>" - and writes one annotation per job worth a look: a warning
for a job that failed in some runs (flaky: timing, ordering, a server), an
error for one that failed in every run (broken, not flaky). Steps that failed
are named, so the annotation says where to look. Exits 0 either way: the
annotations are the result.
"""
import json
import subprocess
import sys
from collections import defaultdict


def classify(jobs):
    """{job name: {run: (conclusion, [failed steps])}} -> (flaky, broken) as sorted lists of names."""
    flaky, broken = [], []
    for name, runs in sorted(jobs.items()):
        outcomes = [conclusion for conclusion, _ in runs.values()]
        failed = [o for o in outcomes if o in ("failure", "timed_out")]
        if not failed:
            continue
        if len(failed) == len(outcomes):
            broken.append(name)
        else:
            flaky.append(name)
    return flaky, broken


def group(raw_jobs):
    """GitHub's job list -> {job name: {run: (conclusion, [failed step names])}}."""
    jobs = defaultdict(dict)
    for job in raw_jobs:
        full = job.get("name", "")
        if " / " not in full or not full.startswith("run "):
            continue
        run, name = full.split(" / ", 1)
        steps = [s.get("name", "?") for s in job.get("steps") or [] if s.get("conclusion") == "failure"]
        jobs[name][run.removeprefix("run ")] = (job.get("conclusion") or "unfinished", steps)
    return jobs


def describe(name, runs):
    parts = []
    for run in sorted(runs):
        conclusion, steps = runs[run]
        parts.append(f"run {run}: {conclusion}" + (f" ({'; '.join(steps)})" if steps else ""))
    return f"{name} - " + ", ".join(parts)


def main(repository, run_id):
    output = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repository}/actions/runs/{run_id}/jobs?per_page=100",
         "--jq", ".jobs[]"],
        check=True, capture_output=True, text=True).stdout
    raw = [json.loads(line) for line in output.splitlines() if line.strip()]
    jobs = group(raw)
    flaky, broken = classify(jobs)
    for name in flaky:
        print(f"::warning title=flaky: {name}::{describe(name, jobs[name])}")
    for name in broken:
        print(f"::error title=failed in every run: {name}::{describe(name, jobs[name])}")
    print(f"{len(jobs)} jobs, {len(flaky)} flaky, {len(broken)} failed in every run")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
