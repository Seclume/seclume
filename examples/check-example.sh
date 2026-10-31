#!/usr/bin/env bash
# The proof for examples/micronaut and examples/helidon:
#
#   ./check-example.sh <example> <main class> <seclume-heapcheck.jar>
#
# 1. The application starts from its configuration file alone, connects
#    through Vault and says who it is.
# 2. seclume-heapcheck takes a heap dump of it and finds no trace of the
#    database password, in any encoding.
# 3. The same application with a password in its configuration (a system
#    property, which both frameworks read as configuration) does not start -
#    and does not print the password while refusing it.
#
# Needs ../getting-started/setup.sh to have run: PostgreSQL and Vault, the
# password in Vault, the trust store for Vault's dev CA. Exit 0 when all
# three hold.
set -euo pipefail
cd "$(dirname "$0")/${1:?usage: check-example.sh <example> <main class> <seclume-heapcheck.jar>}"
main=${2:?the main class}
heapcheck=$(cd "$(dirname "${3:?the seclume-heapcheck jar}")" && pwd)/$(basename "$3")
secrets=../getting-started/secrets
test -s "$secrets/db-password" || { echo "run ../getting-started/setup.sh first" >&2; exit 2; }
logs=target/check
rm -rf "$logs" && mkdir -p "$logs"
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}
trap cleanup EXIT
run() { # run <log> <extra JVM options...>
  local log=$1; shift
  exec java --enable-native-access=ALL-UNNAMED -Djavax.net.ssl.trustStore="$secrets/vault-ca.p12" \
    -Djavax.net.ssl.trustStorePassword=changeit "$@" -cp "target/classes:target/lib/*" "$main" \
    > "$log" 2>&1
}

echo "== $1: from the configuration file alone"
run "$logs/app.log" &
pid=$!
for _ in $(seq 1 90); do
  grep -q "running as pid" "$logs/app.log" && break
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
if ! grep -q "connected as app on PostgreSQL" "$logs/app.log"; then
  echo "the application did not connect; its output is in $logs/app.log" >&2
  tail -40 "$logs/app.log" >&2
  exit 1
fi
grep "connected as" "$logs/app.log" | cut -c1-60
app=$(sed -n 's/.*running as pid //p' "$logs/app.log")

echo "== a heap dump of process $app, searched for the password"
code=0
java --enable-native-access=ALL-UNNAMED -jar "$heapcheck" --pid "$app" \
  --secret-file "$secrets/db-password" --no-attribution > "$logs/check.txt" 2>&1 || code=$?
grep -E "FOUND|^  " "$logs/check.txt" || true
if [ "$code" != 0 ]; then
  echo "the password is in the heap, or the heap could not be searched (exit $code)" >&2
  cat "$logs/check.txt" >&2
  exit 1
fi
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
pid=""

echo "== a password in the configuration"
canary="zl-example-canary-$RANDOM$RANDOM"
code=0
timeout 60 java --enable-native-access=ALL-UNNAMED -Dseclume.datasources.default.password="$canary" \
  -cp "target/classes:target/lib/*" "$main" > "$logs/refused.log" 2>&1 || code=$?
if grep -q "running as pid" "$logs/refused.log" || [ "$code" = 0 ] || [ "$code" = 124 ]; then
  echo "the application started with a password in its configuration (exit $code)" >&2
  tail -40 "$logs/refused.log" >&2
  exit 1
fi
if grep -q "$canary" "$logs/refused.log"; then
  echo "the refusal printed the password" >&2
  exit 1
fi
grep -m1 -o "seclume.datasources.default.password[^\"]*" "$logs/refused.log" | cut -c1-200 || true
echo
echo "$1: connected through Vault, no password in the heap, a configured password refused."
