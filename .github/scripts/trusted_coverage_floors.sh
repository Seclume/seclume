#!/usr/bin/env bash
# The coverage floors as the base branch has them, for a pull request - the
# same reasoning as trusted_gate.sh: a change could lower a floor in the same
# commit that drops the tests it guarded. The base commit's floors and gate
# script are written to $RUNNER_TEMP and COVERAGE_FLOORS / COVERAGE_GATE point
# at them; a change to either applies once merged, on its own.
#
# Outside a pull request the checkout's own files are used.
set -euo pipefail

floors=.github/coverage-floors.json
gate=.github/scripts/coverage_gate.py
if [ "${GITHUB_EVENT_NAME:-}" = pull_request ] && [ -n "${BASE_SHA:-}" ]; then
  trusted="$RUNNER_TEMP/coverage-gate"
  mkdir -p "$trusted"
  git fetch --no-tags --no-recurse-submodules --depth=1 origin "$BASE_SHA"
  git show "$BASE_SHA:$floors" > "$trusted/coverage-floors.json"
  git show "$BASE_SHA:$gate" > "$trusted/coverage_gate.py"
  if ! git diff --quiet "$BASE_SHA" HEAD -- "$floors" "$gate"; then
    echo "::warning title=coverage floors::This pull request changes the coverage floors or their gate. It is checked with the base branch's; the change applies once merged."
  fi
  floors="$trusted/coverage-floors.json"
  gate="$trusted/coverage_gate.py"
  echo "coverage floors from $BASE_SHA"
fi
{
  echo "COVERAGE_FLOORS=$floors"
  echo "COVERAGE_GATE=$gate"
} >> "$GITHUB_ENV"
