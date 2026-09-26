#!/bin/sh
# Does your heap dump contain your database password? A side-by-side run.
#
#   ./run.sh <dir with seclume-core.jar, seclume-postgresql.jar,
#             seclume-heapcheck.jar and postgresql.jar (pgjdbc)>
#
# One pod on a Linux host with podman: PostgreSQL, a Vault dev server (TLS)
# holding the database password, and two copies of the same small application:
# one with the usual stack (Vault answer -> String -> pgjdbc), one with
# seclume. Both connect and keep running. Then seclume-heapcheck asks each JVM
# for a heap dump and searches it for the password and for the Vault token, in
# every encoding they could be in.
#
# The password and the token are random, made for this run, never printed,
# and shredded with everything else at the end.
set -eu
jars=$(cd "$1" && pwd)
here=$(cd "$(dirname "$0")" && pwd)
shared=$(mktemp -d)
cleanup() {
  podman pod rm -f seclume-demo >/dev/null 2>&1 || true
  find "$shared" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$shared"
}
trap cleanup EXIT
chmod 755 "$shared"
head -c 24 /dev/urandom | base64 | tr -d '\n=+/' > "$shared/db-password"
head -c 24 /dev/urandom | base64 | tr -d '\n=+/' > "$shared/vault-token"
chmod 644 "$shared"/*
mkdir "$shared/vault-tls" && chmod 777 "$shared/vault-tls"

# Colour on a terminal only: FOUND in red, NOT FOUND in green.
if [ -t 1 ]; then red=$(printf '[1;31m'); green=$(printf '[1;32m')
  bold=$(printf '[1m'); off=$(printf '[0m')
else red=; green=; bold=; off=; fi
step() { echo "${bold}-> $*${off}"; }

step "PostgreSQL 17 and a Vault dev server; the database password lives in Vault"

podman pod create --name seclume-demo >/dev/null
podman run -d --pod seclume-demo --name seclume-demo-db \
  -e POSTGRES_PASSWORD_FILE=/shared/db-password -v "$shared":/shared:ro,z \
  docker.io/library/postgres:17-alpine >/dev/null
podman run -d --pod seclume-demo --name seclume-demo-vault --cap-add IPC_LOCK \
  -v "$shared":/shared:z --entrypoint sh docker.io/hashicorp/vault:1.20 -c '
    export VAULT_DEV_ROOT_TOKEN_ID="$(cat /shared/vault-token)"
    exec vault server -dev -dev-tls -dev-tls-cert-dir=/shared/vault-tls \
      -dev-listen-address=127.0.0.1:8200' >/dev/null
for i in $(seq 1 60); do
  podman exec seclume-demo-db pg_isready -h 127.0.0.1 -U postgres >/dev/null 2>&1 && \
  [ -f "$shared/vault-tls/vault-ca.pem" ] && break; sleep 1
done
sleep 3
podman exec seclume-demo-vault sh -c '
  VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/shared/vault-tls/vault-ca.pem \
  VAULT_TOKEN="$(cat /shared/vault-token)" \
  vault kv put secret/app password=@/shared/db-password' >/dev/null
step "the same application twice: pgjdbc and seclume, both reading the password from Vault"

podman run -d --pod seclume-demo --name seclume-demo-app \
  -v "$shared":/shared:ro,z -v "$jars":/jars:ro,z -v "$here":/demo:ro,z \
  docker.io/library/eclipse-temurin:25-jdk-alpine sleep infinity >/dev/null
# Both applications trust Vault's dev CA, and nothing else is different.
podman exec seclume-demo-app keytool -importcert -noprompt -alias vault -storetype pkcs12 \
  -file /shared/vault-tls/vault-ca.pem -keystore /tmp/vault-ca.p12 -storepass changeit \
  >/dev/null 2>&1
trust='-Djavax.net.ssl.trustStore=/tmp/vault-ca.p12 -Djavax.net.ssl.trustStorePassword=changeit'
podman exec -d seclume-demo-app sh -c "java $trust -cp /jars/postgresql.jar \
  /demo/VendorApp.java > /tmp/vendor.log 2>&1" >/dev/null
podman exec -d seclume-demo-app sh -c "java $trust --enable-native-access=ALL-UNNAMED \
  -cp /jars/seclume-core.jar:/jars/seclume-postgresql.jar /demo/SeclumeApp.java \
  > /tmp/seclume.log 2>&1" >/dev/null
for i in $(seq 1 60); do
  podman exec seclume-demo-app sh -c \
    'grep -q connected /tmp/vendor.log && grep -q connected /tmp/seclume.log' 2>/dev/null \
    && break; sleep 1
done
step "both connected; now a heap dump of each JVM, searched for the password and the token"
vendor=$(podman exec seclume-demo-app sh -c "sed -n 's/.*pid //p' /tmp/vendor.log")
seclume=$(podman exec seclume-demo-app sh -c "sed -n 's/.*pid //p' /tmp/seclume.log")
if [ -z "$vendor" ] || [ -z "$seclume" ]; then
  echo "an application did not connect:"
  podman exec seclume-demo-app cat /tmp/vendor.log /tmp/seclume.log
  exit 1
fi

check() {
  podman exec seclume-demo-app java -jar /jars/seclume-heapcheck.jar --pid "$1" \
    --secret-file "$2" | grep -E '^(FOUND|NOT FOUND|  )'     | sed -e "s/^NOT FOUND/${green}NOT FOUND${off}/" -e "s/^FOUND/${red}FOUND${off}/"           -e 's/^/    /' || true
}
for app in vendor seclume; do
  if [ "$app" = vendor ]; then
    pid=$vendor; label="pgjdbc - the password from Vault as a String"
  else
    pid=$seclume; label="seclume - the password from Vault into native memory"
  fi
  echo
  echo "${bold}== $label${off}"
  echo "  database password:"
  check "$pid" /shared/db-password
  echo "  Vault token:"
  check "$pid" /shared/vault-token
done
