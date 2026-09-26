#!/bin/sh
# The CRaC proof, on a Linux host with podman (rootful: CRaC needs privileges).
#
#   ./run.sh <dir with the five jars>
#
# 1. A throwaway PostgreSQL with a random password (never printed).
# 2. register: a pool registered with SeclumeCrac is checkpointed, restored,
#    and queried again - over a new login.
# 3. The checkpoint image is searched for the password: 0 matches expected.
# 4. leak (control): the same, with the password held as a String on purpose -
#    the search has to find it, or step 3 proves nothing.
# 5. bare (control): the pool not registered - CRaC has to refuse the
#    checkpoint over the open sockets.
# Everything is removed at the end, the images first (the leak one holds the
# password).
set -eu
jars=$(cd "$1" && pwd)
work=$(mktemp -d)
trap 'podman rm -f seclume-crac-pg >/dev/null 2>&1 || true; find "$work" -type f -exec shred -u {} \; ; rm -rf "$work"' EXIT
cp "$jars"/*.jar "$(dirname "$0")/CracProof.java" "$work/"
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$work/pw"
chmod 600 "$work/pw"
podman run -d --name seclume-crac-pg -p 5442:5432 -e POSTGRES_USER=seclume_test \
  -e POSTGRES_DB=seclume_test -e POSTGRES_PASSWORD="$(cat "$work/pw")" \
  -e POSTGRES_HOST_AUTH_METHOD=scram-sha-256 -e POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 \
  docker.io/library/postgres:16 >/dev/null
for i in $(seq 1 30); do podman exec seclume-crac-pg pg_isready -U seclume_test >/dev/null 2>&1 && break; sleep 1; done
sleep 2
cp=$(cd "$work" && ls *.jar | sed 's|^|/work/|' | paste -sd: -)
jdk=docker.io/azul/zulu-openjdk:25-jdk-crac
run() { podman run --rm --privileged --network host -v "$work":/work:Z "$jdk" java "$@"; }
matches() { grep -a -c -F "$(tr -d '\r\n' < "$work/pw")" "$work"/cr/* 2>/dev/null | awk -F: '{s+=$2} END {print s+0}'; }

for mode in register leak bare; do
  rm -rf "$work/cr"; mkdir "$work/cr"
  echo "== $mode"
  run --enable-native-access=ALL-UNNAMED -XX:CRaCCheckpointTo=/work/cr -cp "$cp" /work/CracProof.java "$mode" | grep PROOF || true
  if [ "$mode" = register ]; then
    run -XX:CRaCRestoreFrom=/work/cr | grep PROOF
  fi
  echo "   password in the image: $(matches) matches"
done
