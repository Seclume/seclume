#!/bin/sh
# A PostgreSQL login by Kerberos, on a Linux host with podman:
#
#   ./kerberos.sh <dir with seclume-core.jar and seclume-postgresql.jar>
#
# A KDC (realm SECLUME.TEST), a PostgreSQL 16 that accepts alice by 'gss', and a
# JDK 25 client that gets a ticket from a keytab and logs in with no password.
# The control: the same client without a ticket has to be refused.
# The realm's master password and the keytabs are made here, for this run, and
# removed with everything else at the end.
set -eu
# Every mount is ':z', the shared SELinux label: ':Z' gives a directory to one
# container, and the next ':Z' takes it away again - the database then cannot
# read its keytab and says "Key table entry not found".
jars=$(cd "$1" && pwd)
proof=$(cd "$(dirname "$0")" && pwd)
shared=$(mktemp -d)
cleanup() {
  podman rm -f seclume-kdc seclume-krb-pg >/dev/null 2>&1 || true
  podman network rm seclume-krb >/dev/null 2>&1 || true
  find "$shared" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$shared"
}
trap cleanup EXIT
chmod 755 "$shared"

cat > "$shared/krb5.conf" <<'EOF'
[libdefaults]
  default_realm = SECLUME.TEST
  dns_lookup_realm = false
  dns_lookup_kdc = false
  rdns = false
  dns_canonicalize_hostname = false
[realms]
  SECLUME.TEST = {
    kdc = kdc.seclume.test
    admin_server = kdc.seclume.test
  }
[domain_realm]
  .seclume.test = SECLUME.TEST
EOF
cat > "$shared/init-gss.sh" <<'EOF'
#!/bin/sh
sed -i '1i host all alice all gss include_realm=0' "$PGDATA/pg_hba.conf"
psql -U postgres -c "create role alice login"
EOF
chmod 644 "$shared"/*

podman network create seclume-krb >/dev/null
podman run -d --name seclume-kdc --network seclume-krb --network-alias kdc.seclume.test \
  -v "$shared":/shared:z docker.io/library/alpine:3.22 sh -c '
    apk add -q krb5-server krb5 >/dev/null
    cp /shared/krb5.conf /etc/krb5.conf
    kdb5_util create -s -r SECLUME.TEST -P "$(head -c 24 /dev/urandom | base64)" >/dev/null 2>&1
    kadmin.local -q "addprinc -randkey postgres/pg.seclume.test" >/dev/null 2>&1
    kadmin.local -q "addprinc -randkey alice" >/dev/null 2>&1
    kadmin.local -q "ktadd -k /shared/pg.keytab postgres/pg.seclume.test" >/dev/null 2>&1
    kadmin.local -q "ktadd -k /shared/alice.keytab alice" >/dev/null 2>&1
    chmod 644 /shared/pg.keytab /shared/alice.keytab
    exec krb5kdc -n' >/dev/null
for i in $(seq 1 60); do [ -f "$shared/alice.keytab" ] && break; sleep 1; done
sleep 2

podman run -d --name seclume-krb-pg --network seclume-krb --network-alias pg.seclume.test \
  -v "$shared":/shared:z -e POSTGRES_PASSWORD="$(head -c 24 /dev/urandom | base64)" \
  -v "$shared/init-gss.sh":/docker-entrypoint-initdb.d/init-gss.sh:z \
  docker.io/library/postgres:16 -c krb_server_keyfile=/shared/pg.keytab >/dev/null
for i in $(seq 1 60); do podman exec seclume-krb-pg pg_isready -U postgres >/dev/null 2>&1 && break; sleep 1; done
sleep 3

client() {
  podman run --rm --network seclume-krb -v "$shared":/shared:ro,z -v "$jars":/jars:ro,z \
    -v "$proof":/proof:ro,z -e KRB5_CONFIG=/shared/krb5.conf \
    docker.io/library/eclipse-temurin:25-jdk-alpine sh -c "
      apk add -q krb5 >/dev/null
      $1
      java --enable-native-access=ALL-UNNAMED \
        -cp /jars/seclume-core.jar:/jars/seclume-postgresql.jar /proof/KerberosProof.java"
}
echo "== with a ticket (kinit from alice's keytab)"
client "kinit -kt /shared/alice.keytab alice@SECLUME.TEST" | grep PROOF
echo "== control: no ticket"
client "true" | grep PROOF
