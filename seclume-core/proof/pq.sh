#!/bin/sh
# X25519MLKEM768 against OpenSSL, on a Linux host with podman:
#
#   ./pq.sh <dir with seclume-core.jar>
#
# In an Alpine container with a JDK 25 and OpenSSL 3.5, seclume's TLS client
# connects to `openssl s_server` three times:
#   1. the server offers only X25519MLKEM768 - the hybrid has to be negotiated;
#   2. the server offers only P-256 - the client has to fall back at once;
#   3. the control: the hybrid-only server, with -Dseclume.tls.postQuantum=false -
#      it has to fail, or run 1 proves nothing.
set -eu
jars=$(cd "$1" && pwd)
proof=$(cd "$(dirname "$0")" && pwd)
podman run --rm -v "$jars":/jars:ro,Z -v "$proof":/proof:ro,Z \
  docker.io/library/eclipse-temurin:25-jdk-alpine sh -c '
    apk add -q openssl >/dev/null
    echo "openssl $(openssl version)"
    cd /tmp
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost \
      -keyout key.pem -out cert.pem -days 1 2>/dev/null
    run() {
      openssl s_server -accept 4433 -tls1_3 -groups "$1" -key key.pem -cert cert.pem -quiet \
        </dev/null >/dev/null 2>&1 &
      server=$!
      sleep 1
      java --enable-native-access=ALL-UNNAMED $2 -cp /jars/seclume-core.jar /proof/PqProof.java | grep PROOF
      kill $server 2>/dev/null || true
      wait $server 2>/dev/null || true
    }
    echo "== server: X25519MLKEM768 only";  run X25519MLKEM768 ""
    echo "== server: P-256 only";           run P-256 ""
    echo "== control: hybrid-only server, post-quantum switched off"
    run X25519MLKEM768 "-Dseclume.tls.postQuantum=false"
  '
