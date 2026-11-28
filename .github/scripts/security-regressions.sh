#!/bin/sh
# Runs the test classes .github/security-regressions.txt lists, together, and
# fails when one of them did not run: a class renamed or moved, or all of its
# tests skipped, would otherwise pass this job without a word.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
list=.github/security-regressions.txt
entries=$(grep -v '^[[:space:]]*#' "$list" | grep -v '^[[:space:]]*$')
modules=$(printf '%s\n' "$entries" | cut -d: -f1 | sort -u | paste -sd, -)
classes=$(printf '%s\n' "$entries" | cut -d: -f2 | sort -u | paste -sd, -)

./mvnw -B -pl "$modules" -am test -Dtest="$classes" -Dsurefire.failIfNoSpecifiedTests=false "$@"

missing=0
for entry in $entries; do
    module=${entry%%:*}
    class=${entry#*:}
    report=$(find "$module/target/surefire-reports" -name "TEST-*.$class.xml" 2>/dev/null | head -1)
    if [ -z "$report" ]; then
        echo "::error::$module:$class did not run"
        missing=$((missing + 1))
        continue
    fi
    tests=$(sed -n 's/.*<testsuite[^>]* tests="\([0-9]*\)".*/\1/p' "$report" | head -1)
    skipped=$(sed -n 's/.*<testsuite[^>]* skipped="\([0-9]*\)".*/\1/p' "$report" | head -1)
    if [ "${tests:-0}" -eq 0 ] || [ "${tests:-0}" -eq "${skipped:-0}" ]; then
        echo "::error::$module:$class ran no test (${tests:-0} tests, ${skipped:-0} skipped)"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt 0 ]; then
    echo "$missing security regression class(es) did not run"
    exit 1
fi
echo "all $(printf '%s\n' "$entries" | wc -l) security regression classes ran"
