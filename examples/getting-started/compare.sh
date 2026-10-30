#!/usr/bin/env bash
# The same application twice - the usual way and with seclume - and a heap dump
# of each, searched for the database password by seclume-heapcheck.
#
#   ./compare.sh <seclume-heapcheck.jar>
#
# Exit 0 when the usual way leaks the password and seclume does not - which is
# what this example is here to show; 1 otherwise.
set -euo pipefail
cd "$(dirname "$0")"
heapcheck=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
jar=$(ls target/seclume-getting-started-*.jar | grep -v original | head -1)
# The applications' output, kept for a look when something fails.
logs=target/compare
rm -rf "$logs" && mkdir -p "$logs"
cleanup() {
  for pid in $(cat "$logs"/*.pid 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  rm -f "$logs/check.txt"
}
trap cleanup EXIT

start() { # start <profile> -> the JVM's pid, once it is connected
  local profile=$1
  if [ "$profile" = plain ]; then
    # The usual way: the password in the environment, read by Spring into a String.
    SPRING_DATASOURCE_PASSWORD="$(cat secrets/db-password)" \
      java -jar "$jar" --spring.profiles.active=plain > "$logs/$profile.log" 2>&1 &
  else
    java --enable-native-access=ALL-UNNAMED -Djavax.net.ssl.trustStore=secrets/vault-ca.p12 \
      -Djavax.net.ssl.trustStorePassword=changeit -jar "$jar" \
      --spring.profiles.active=seclume > "$logs/$profile.log" 2>&1 &
  fi
  echo $! > "$logs/$profile.pid"
  for _ in $(seq 1 90); do
    grep -q "running as pid" "$logs/$profile.log" && break
    sleep 1
  done
  if ! grep -q "connected as" "$logs/$profile.log"; then
    echo "the $profile application did not connect; its output is in $logs/$profile.log" >&2
    tail -40 "$logs/$profile.log" >&2
    exit 2
  fi
  sed -n 's/.*running as pid //p' "$logs/$profile.log"
}

check() { # check <pid> -> heapcheck's exit code: 0 not found, 1 found
  local code=0
  java --enable-native-access=ALL-UNNAMED -jar "$heapcheck" --pid "$1" \
    --secret-file secrets/db-password --no-attribution > "$logs/check.txt" 2>&1 || code=$?
  grep -E "FOUND|^  " "$logs/check.txt" || true
  return "$code"
}

echo "== the usual way: HikariCP and pgjdbc, the password from the environment"
plain=$(start plain)
plain_code=0; check "$plain" || plain_code=$?
echo
echo "== seclume: the password from Vault into native memory"
seclume=$(start seclume)
seclume_code=0; check "$seclume" || seclume_code=$?
echo
if [ "$plain_code" = 1 ] && [ "$seclume_code" = 0 ]; then
  echo "The usual way leaves the password in every heap dump; seclume does not."
  exit 0
fi
echo "unexpected: the usual way exited $plain_code (1 expected), seclume $seclume_code (0 expected)"
exit 1
