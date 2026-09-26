#!/bin/sh
# A MariaDB login by Kerberos (auth_gssapi), on a Linux host with podman:
#
#   ./kerberos.sh <dir with seclume-core.jar and seclume-mysql.jar>
#
# A KDC (realm SECLUME.TEST), a MariaDB 11.4 with the auth_gssapi plugin and a
# user alice IDENTIFIED VIA gssapi, and a JDK 25 client that gets a ticket from
# a keytab and logs in with no password. The control: the same client without
# a ticket has to be refused. Every key is made here, for this run, and
# removed with everything else at the end.
set -eu
# Every mount is ':z', the shared SELinux label - see the PostgreSQL proof.
jars=$(cd "$1" && pwd)
proof=$(cd "$(dirname "$0")" && pwd)
shared=$(mktemp -d)
cleanup() {
  podman rm -f seclume-kdc seclume-krb-maria >/dev/null 2>&1 || true
  podman network rm seclume-krb >/dev/null 2>&1 || true
  find "$shared" -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf "$shared"
}
trap cleanup EXIT
chmod 755 "$shared"

cat > "$shared/krb5.conf" <<'CONF'
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
CONF
cat > "$shared/init-gss.sql" <<'SQL'
create user alice identified via gssapi;
SQL
chmod 644 "$shared"/*

podman network create seclume-krb >/dev/null
podman run -d --name seclume-kdc --network seclume-krb --network-alias kdc.seclume.test \
  -v "$shared":/shared:z docker.io/library/alpine:3.22 sh -c '
    apk add -q krb5-server krb5 >/dev/null
    cp /shared/krb5.conf /etc/krb5.conf
    kdb5_util create -s -r SECLUME.TEST -P "$(head -c 24 /dev/urandom | base64)" >/dev/null 2>&1
    kadmin.local -q "addprinc -randkey mariadb/maria.seclume.test" >/dev/null 2>&1
    kadmin.local -q "addprinc -randkey alice" >/dev/null 2>&1
    kadmin.local -q "ktadd -k /shared/maria.keytab mariadb/maria.seclume.test" >/dev/null 2>&1
    kadmin.local -q "ktadd -k /shared/alice.keytab alice" >/dev/null 2>&1
    chmod 644 /shared/maria.keytab /shared/alice.keytab
    exec krb5kdc -n' >/dev/null
for i in $(seq 1 60); do [ -f "$shared/alice.keytab" ] && break; sleep 1; done
sleep 2

# The official image has no auth_gssapi; the package comes from its own repository.
podman run -d --name seclume-krb-maria --network seclume-krb --network-alias maria.seclume.test \
  -v "$shared":/shared:z -e KRB5_CONFIG=/shared/krb5.conf \
  -e MARIADB_ROOT_PASSWORD="$(head -c 24 /dev/urandom | base64)" \
  -v "$shared/init-gss.sql":/docker-entrypoint-initdb.d/init-gss.sql:z \
  --entrypoint sh docker.io/library/mariadb:11.4 -c '
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq mariadb-plugin-gssapi-server >/dev/null 2>&1
    exec docker-entrypoint.sh mariadbd --plugin-load-add=auth_gssapi.so \
      --gssapi-keytab-path=/shared/maria.keytab \
      --gssapi-principal-name=mariadb/maria.seclume.test@SECLUME.TEST' >/dev/null
for i in $(seq 1 180); do
  podman logs seclume-krb-maria 2>&1 | grep -q "port: 3306" && break; sleep 1
done
sleep 2

client() {
  podman run --rm --network seclume-krb -v "$shared":/shared:ro,z -v "$jars":/jars:ro,z \
    -v "$proof":/proof:ro,z -e KRB5_CONFIG=/shared/krb5.conf \
    docker.io/library/eclipse-temurin:25-jdk-alpine sh -c "
      apk add -q krb5 >/dev/null
      $1
      java --enable-native-access=ALL-UNNAMED \
        -cp /jars/seclume-core.jar:/jars/seclume-mysql.jar /proof/KerberosProof.java"
}
echo "== with a ticket (kinit from alice's keytab)"
client "kinit -kt /shared/alice.keytab alice@SECLUME.TEST" | grep PROOF
echo "== control: no ticket"
client "true" | grep PROOF
