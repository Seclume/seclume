#!/usr/bin/env bash
# mvnw-retry.sh <mvnw arguments>: ./mvnw, again - up to twice - when it fails
# before it has built anything.
#
# Now and then a CI job's Maven step ended after 0 seconds, before the
# reactor was even listed: a runner that could not fetch the wrapper's Maven
# or a plugin at that moment, never the code. Such a failure is retried after
# a pause and reported as a warning with Maven's last lines; any failure
# after the build has started - a compiler error, a test - is passed on
# untouched, the first time.
set -uo pipefail
code=1
for attempt in 1 2 3; do
  log=$(mktemp)
  start=$(date +%s)
  ./mvnw "$@" 2>&1 | tee "$log"
  code=${PIPESTATUS[0]}
  elapsed=$(( $(date +%s) - start ))
  if [ "$code" = 0 ]; then
    rm -f "$log"
    exit 0
  fi
  if [ "$elapsed" -ge 60 ] || grep -q "Reactor Build Order\|Building seclume\|BUILD FAILURE\|Tests run:" "$log"; then
    rm -f "$log"
    exit "$code"
  fi
  tail=$(tail -c 1200 "$log" | sed 's/%/%25/g' | tr '\n' ' ')
  rm -f "$log"
  echo "::warning title=mvnw attempt ${attempt}::exited ${code} after ${elapsed}s before building anything: ${tail}"
  [ "$attempt" = 3 ] || sleep $(( attempt * ${MVNW_RETRY_PAUSE:-15} ))
done
exit "$code"
