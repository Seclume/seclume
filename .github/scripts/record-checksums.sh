#!/bin/sh
# Records the SHA-256 of every artifact and plugin the build resolves into
# .mvn/checksums, which CI then checks every download against (MAVEN_ARGS in
# the workflows). Run it after a dependency or plugin changed - a Dependabot
# update too - and review the diff: each new line is a file this project now
# trusts. Entries are only ever added; an existing one that no longer matches
# fails the build instead of being replaced.
#
#   .github/scripts/record-checksums.sh            # the test build
#   .github/scripts/record-checksums.sh -Prelease  # and anything else run in CI
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
basedir="$root/.mvn/checksums"
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) basedir=$(cd "$basedir" && pwd -W) ;;
esac
./mvnw -B -Dgpg.skip=true -DskipTests=false \
    -Daether.artifactResolver.postProcessor.trustedChecksums=true \
    -Daether.artifactResolver.postProcessor.trustedChecksums.record=true \
    -Daether.artifactResolver.postProcessor.trustedChecksums.checksumAlgorithms=SHA-256 \
    -Daether.trustedChecksumsSource.summaryFile=true \
    -Daether.trustedChecksumsSource.summaryFile.basedir="$basedir" \
    "$@" verify
# The resolver keeps the previous file as .bak; the diff is what to review.
rm -f "$basedir"/*.bak
git diff --stat -- .mvn/checksums
