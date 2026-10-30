#!/usr/bin/env bash
# Builds the image of the webhook and its sidecar from the jars of
#   ./mvnw -pl seclume-admission,seclume-heapcheck -am package -DskipTests
# usage: build-image.sh <tag>
set -euo pipefail
tag=${1:?usage: build-image.sh <tag>}
root=$(cd "$(dirname "$0")/../.." && pwd)
context=$(mktemp -d)
trap 'rm -rf "$context"' EXIT
jar() { # the shaded jar of a module: not original-, sources or javadoc
  find "$root/$1/target" -maxdepth 1 -name "$1-*.jar" ! -name '*-sources.jar' \
    ! -name '*-javadoc.jar' ! -name '*-tests.jar' | head -1
}
admission=$(jar seclume-admission)
heapcheck=$(jar seclume-heapcheck)
test -n "$admission" && test -n "$heapcheck" || {
  echo "build the jars first: ./mvnw -pl seclume-admission,seclume-heapcheck -am package -DskipTests" >&2
  exit 2
}
cp "$admission" "$context/seclume-admission.jar"
cp "$heapcheck" "$context/seclume-heapcheck.jar"
docker build -q -t "$tag" -f "$root/seclume-admission/Dockerfile" "$context"
