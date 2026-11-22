#!/usr/bin/env bash
# The security gate as the base branch has it, for a pull request.
#
# On a pull request the checkout is the change under review: its manifest
# (.github/security-gate.json) and its gate script decide what "the security
# tests passed" means, so a change could relax both in the same commit that
# weakens a test. This fetches the base commit and writes the base branch's
# manifest and script to $RUNNER_TEMP, and points SECURITY_GATE and
# SECURITY_GATE_MANIFEST at them for the steps after it. A change to the gate
# therefore takes effect only once it is merged, on its own, and reviewed.
#
# The limit: the workflow file is part of the change too. This holds only
# where changes to .github/ need a code owner's review before they run with
# secrets or merge (branch protection, CODEOWNERS); it moves a relaxed gate
# into the workflow diff, where a review sees it, and does not replace that.
set -euo pipefail

if [ "${GITHUB_EVENT_NAME:-}" != pull_request ] || [ -z "${BASE_SHA:-}" ]; then
  echo "not a pull request: the gate runs from the checkout"
  exit 0
fi

gate="$RUNNER_TEMP/security-gate"
mkdir -p "$gate"
git fetch --no-tags --no-recurse-submodules --depth=1 origin "$BASE_SHA"
git show "$BASE_SHA:.github/security-gate.json" > "$gate/security-gate.json"
git show "$BASE_SHA:.github/scripts/security_gate.py" > "$gate/security_gate.py"
{
  echo "SECURITY_GATE=$gate/security_gate.py"
  echo "SECURITY_GATE_MANIFEST=$gate/security-gate.json"
} >> "$GITHUB_ENV"

if ! git diff --quiet "$BASE_SHA" HEAD -- .github/security-gate.json .github/scripts/security_gate.py; then
  echo "::warning title=security gate::This pull request changes the security gate. It is checked with the base branch's manifest and script; the change applies once merged."
fi
echo "security gate from $BASE_SHA"
