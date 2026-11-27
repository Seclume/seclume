#!/bin/sh
# Two restores of one checkpoint image must not draw the same random bytes.
#
#   ./run-random.sh <dir with seclume-core, seclume-pool, seclume-crac and crac jars>
#
# For each mode one checkpoint, restored twice; CracRandomProof prints 32 bytes
# of OpenSSL's generator after each restore. "register" must print different
# bytes. "bare" is the control: in a container the restored process gets
# another pid, OpenSSL takes that for a fork and reseeds by itself, so it
# differs too - where a snapshot keeps the pid (a VM snapshot, Lambda
# SnapStart), only the reseed SeclumeCrac makes after the restore separates
# the two.
set -eu
jars=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$jars"/*.jar "$(dirname "$0")/CracRandomProof.java" "$work/"
cp=$(cd "$work" && ls *.jar | sed 's|^|/work/|' | paste -sd: -)
jdk=docker.io/azul/zulu-openjdk:25-jdk-crac
run() { podman run --rm --privileged --network host -v "$work":/work:Z "$jdk" java "$@"; }
for mode in register bare; do
  rm -rf "$work/cr"; mkdir "$work/cr"
  run --enable-native-access=ALL-UNNAMED -XX:CRaCCheckpointTo=/work/cr -cp "$cp" \
      /work/CracRandomProof.java "$mode" >/dev/null
  first=$(run -XX:CRaCRestoreFrom=/work/cr | grep PROOF)
  second=$(run -XX:CRaCRestoreFrom=/work/cr | grep PROOF)
  echo "$mode: $first"
  echo "$mode: $second"
  if [ "$first" = "$second" ]; then
    echo "$mode: the same bytes after both restores"
    [ "$mode" = register ] && exit 1
  fi
done
