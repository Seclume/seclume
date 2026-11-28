#!/bin/sh
# A checkpoint slower than seclume's hold must not let a secret be made
# before the image is written.
#
#   ./run-hold.sh <dir with seclume-core, seclume-pool, seclume-crac and crac jars>
#
# CracHoldProof registers a resource before seclume - notified after it - that
# takes 3 s, with seclume.crac.holdMillis=1000, and asks for secrets meanwhile.
# holdExpiry=refuse (the default) must print "made during the checkpoint:
# false"; holdExpiry=release (the opt-out) is the control and prints true.
set -eu
jars=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$jars"/*.jar "$(dirname "$0")/CracHoldProof.java" "$work/"
cp=$(cd "$work" && ls *.jar | sed 's|^|/work/|' | paste -sd: -)
jdk=docker.io/azul/zulu-openjdk:25-jdk-crac
run() { podman run --rm --privileged --network host -v "$work":/work:Z "$jdk" java "$@"; }
for expiry in refuse release; do
  rm -rf "$work/cr"; mkdir "$work/cr"
  echo "== seclume.crac.holdExpiry=$expiry"
  run --enable-native-access=ALL-UNNAMED -Dseclume.crac.holdMillis=1000 \
      -Dseclume.crac.holdExpiry=$expiry -XX:CRaCCheckpointTo=/work/cr -cp "$cp" \
      /work/CracHoldProof.java >/dev/null
  out=$(run -XX:CRaCRestoreFrom=/work/cr | grep PROOF)
  echo "$out"
  if [ "$expiry" = refuse ] && echo "$out" | grep -q "during the checkpoint: true"; then
    exit 1
  fi
done
