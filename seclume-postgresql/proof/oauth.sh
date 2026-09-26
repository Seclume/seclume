#!/bin/sh
# A PostgreSQL 18 login by OAuth bearer token, on a Linux host with podman:
#
#   ./oauth.sh <dir with seclume-core.jar and seclume-postgresql.jar>
#
# PostgreSQL 18 with TLS, 'oauth' in pg_hba.conf and a minimal validator
# (tokenval.c: the token in /shared/token is valid), and a JDK 25 client that
# reads its token through the file provider. The control: a different token
# has to be refused. Both tokens are random, made for this run and shredded.
set -eu
jars=$(cd "$1" && pwd)
proof=$(cd "$(dirname "$0")" && pwd)
shared=$(mktemp -d)
cleanup() {
  podman rm -f seclume-pg18-oauth >/dev/null 2>&1 || true
  podman network rm seclume-oauth >/dev/null 2>&1 || true
  find "$shared" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$shared"
}
trap cleanup EXIT
chmod 755 "$shared"
head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_' > "$shared/token"
head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_' > "$shared/other-token"
cp "$proof/tokenval.c" "$shared/"
cat > "$shared/init-oauth.sh" <<'INIT'
#!/bin/sh
sed -i '1i hostssl all alice all oauth issuer="https://issuer.seclume.test" scope="openid"' "$PGDATA/pg_hba.conf"
psql -U postgres -c "create role alice login"
INIT
chmod 644 "$shared"/*

podman network create seclume-oauth >/dev/null
podman run -d --name seclume-pg18-oauth --network seclume-oauth --network-alias pg18.seclume.test \
  -v "$shared":/shared:z -e POSTGRES_PASSWORD="$(head -c 24 /dev/urandom | base64)" \
  -v "$shared/init-oauth.sh":/docker-entrypoint-initdb.d/init-oauth.sh:z \
  --entrypoint sh docker.io/library/postgres:18 -c '
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq gcc postgresql-server-dev-18 libkrb5-dev openssl >/dev/null 2>&1
    gcc -shared -fPIC -I"$(pg_config --includedir-server)" -o "$(pg_config --pkglibdir)/tokenval.so" /shared/tokenval.c
    mkdir -p /etc/pgtls
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
      -subj /CN=pg18.seclume.test -keyout /etc/pgtls/key.pem -out /etc/pgtls/cert.pem 2>/dev/null
    chown postgres /etc/pgtls/*; chmod 600 /etc/pgtls/key.pem
    cp /etc/pgtls/cert.pem /shared/pg-cert.pem; chmod 644 /shared/pg-cert.pem
    exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/etc/pgtls/cert.pem \
      -c ssl_key_file=/etc/pgtls/key.pem -c oauth_validator_libraries=tokenval' >/dev/null
for i in $(seq 1 240); do
  podman logs seclume-pg18-oauth 2>&1 | grep -q "PostgreSQL init process complete" && \
  podman exec seclume-pg18-oauth pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1
done
sleep 2

client() {
  podman run --rm --network seclume-oauth -v "$shared":/shared:ro,z -v "$jars":/jars:ro,z \
    -v "$proof":/proof:ro,z docker.io/library/eclipse-temurin:25-jdk-alpine \
    java --enable-native-access=ALL-UNNAMED \
      -cp /jars/seclume-core.jar:/jars/seclume-postgresql.jar /proof/OAuthProof.java "$1" "$2"
}
verified='tls=verify-full&tlsRootCert=/shared/pg-cert.pem'
echo "== the token the validator accepts, to a server whose certificate is checked"
client /shared/token "$verified" | grep PROOF
echo "== control: another token"
client /shared/other-token "$verified" | grep PROOF
echo "== control: encrypted but unchecked (tls=require) - the token must not go out"
client /shared/token "tls=require" | grep PROOF
