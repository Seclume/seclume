#!/usr/bin/env bash
# mvnw-retry.sh <mvnw arguments>: ./mvnw, again - up to three more times - when
# it fails before it has built anything.
#
# Now and then a CI job's Maven step ended after 0 seconds, before the
# reactor was even listed: a runner that could not fetch the wrapper's jar,
# its Maven or a plugin at that moment, never the code. Such a failure is
# retried after a pause and reported as a warning with Maven's last lines;
# any failure after the build has started - a compiler error, a test - is
# passed on untouched, the first time.
#
# The pauses grow and carry a random part: when the flake hunt starts three
# copies of every job at once, they all ask Maven Central for the wrapper in
# the same second, and retrying in step would only ask again together.
#
# The wrapper's jar is not in the repository, and setup-java's cache holds
# ~/.m2/repository but not .mvn/wrapper. So a jar the wrapper has fetched is
# kept in ~/.m2/repository, where Maven itself would put it, and a job whose
# restored cache has it takes it from there instead of from the network -
# each only when its SHA-256 is the one maven-wrapper.properties names.
set -uo pipefail

properties=.mvn/wrapper/maven-wrapper.properties
jar=.mvn/wrapper/maven-wrapper.jar
setting() {
  sed -n "s/^$1=//p" "$properties" 2>/dev/null | tr -d '\r' | head -1
}
version=$(setting wrapperVersion)
sum=$(setting wrapperSha256Sum)
kept="${MVNW_REPOSITORY:-$HOME/.m2/repository}/org/apache/maven/wrapper/maven-wrapper/${version}/maven-wrapper-${version}.jar"

genuine() {
  [ -s "$1" ] && [ -n "$sum" ] && echo "$sum  $1" | sha256sum -c - >/dev/null 2>&1
}

if [ -n "$version" ] && [ ! -s "$jar" ] && genuine "$kept"; then
  cp "$kept" "$jar" && echo "mvnw-retry: the wrapper jar ${version} from the local repository"
fi

keep_jar() {
  if [ -n "$version" ] && [ ! -s "$kept" ] && genuine "$jar"; then
    mkdir -p "$(dirname "$kept")" && cp "$jar" "$kept"
  fi
}

pause=${MVNW_RETRY_PAUSE:-20}
attempts=${MVNW_RETRY_ATTEMPTS:-4}
code=1
for attempt in $(seq 1 "$attempts"); do
  log=$(mktemp)
  start=$(date +%s)
  ./mvnw "$@" 2>&1 | tee "$log"
  code=${PIPESTATUS[0]}
  elapsed=$(( $(date +%s) - start ))
  keep_jar
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
  if [ "$attempt" != "$attempts" ]; then
    sleep $(( attempt * pause + RANDOM % (pause + 1) ))
  fi
done
exit "$code"
