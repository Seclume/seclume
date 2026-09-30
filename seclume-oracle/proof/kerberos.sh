#!/bin/sh
# An Oracle login by Kerberos, all in containers on one podman network:
#
#   kerberos.sh up                    an MIT KDC for SECLUME.TEST, Oracle Free 23 as
#                                     ora.seclume.test with SQLNET.AUTHENTICATION_SERVICES
#                                     = (KERBEROS5) and a keytab for oracle/ora.seclume.test,
#                                     the database user KALICE identified externally as
#                                     alice@SECLUME.TEST, and a client with MIT Kerberos
#   kerberos.sh run <dir with seclume-core.jar and seclume-oracle.jar> [URL options]
#                                     the proof with a ticket for alice, and without one
#   kerberos.sh down                  all of it removed
set -eu
D=/tmp/seclume-ora-krb
NET=seclume-ora-krb
case "$1" in
up)
  mkdir -p $D && chmod 755 $D
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/admin; chmod 600 $D/admin
  printf '[libdefaults]\n default_realm = SECLUME.TEST\n dns_lookup_kdc = false\n rdns = false\n[realms]\n SECLUME.TEST = {\n  kdc = kdc.seclume.test\n }\n[domain_realm]\n .seclume.test = SECLUME.TEST\n' > $D/krb5.conf
  chmod 644 $D/krb5.conf
  podman network create $NET >/dev/null
  podman run -d --name seclume-ora-kdc --network $NET --network-alias kdc.seclume.test \
    -v $D:/shared:z docker.io/library/alpine:3.22 sh -c '
      apk add -q krb5-server krb5 >/dev/null
      cp /shared/krb5.conf /etc/krb5.conf
      kdb5_util create -s -r SECLUME.TEST -P "$(head -c 24 /dev/urandom | base64)" >/dev/null 2>&1
      kadmin.local -q "addprinc -randkey oracle/ora.seclume.test" >/dev/null 2>&1
      kadmin.local -q "addprinc -randkey alice" >/dev/null 2>&1
      kadmin.local -q "ktadd -k /shared/oracle.keytab oracle/ora.seclume.test" >/dev/null 2>&1
      kadmin.local -q "ktadd -k /shared/alice.keytab alice" >/dev/null 2>&1
      chmod 644 /shared/oracle.keytab /shared/alice.keytab
      exec krb5kdc -n' >/dev/null
  for i in $(seq 1 60); do [ -f $D/alice.keytab ] && break; sleep 1; done
  printf 'ORACLE_PASSWORD=%s\n' "$(cat $D/admin)" > $D/env; chmod 600 $D/env
  podman run -d --name seclume-ora-krb --network $NET --network-alias ora.seclume.test \
    --hostname ora.seclume.test -v $D:/shared:z --env-file $D/env \
    docker.io/gvenzl/oracle-free:23-slim >/dev/null
  shred -u $D/env
  for i in $(seq 1 120); do
    podman logs seclume-ora-krb 2>&1 | grep -q "DATABASE IS READY TO USE" && break
    sleep 5
  done
  # The user first, the password through stdin: the container runs as oracle, and a
  # copied file would be root's.
  podman exec -i seclume-ora-krb sh -c 'P=$(cat)
    printf "%s\n" "alter session set container = FREEPDB1;" \
      "create user kalice identified externally as '"'"'alice@SECLUME.TEST'"'"';" \
      "grant create session to kalice;" "exit" \
      | sqlplus -s "system/$P@localhost/FREEPDB1" >/dev/null' < $D/admin
  # Kerberos only now: the sqlplus above would try it too, without a ticket.
  podman exec seclume-ora-krb sh -c 'cat >> "$ORACLE_HOME/network/admin/sqlnet.ora" <<EOF
SQLNET.AUTHENTICATION_SERVICES = (BEQ, KERBEROS5)
SQLNET.AUTHENTICATION_KERBEROS5_SERVICE = oracle
SQLNET.KERBEROS5_CONF = /shared/krb5.conf
SQLNET.KERBEROS5_CONF_MIT = TRUE
SQLNET.KERBEROS5_KEYTAB = /shared/oracle.keytab
EOF'
  podman run -d --name seclume-ora-krb-client --network $NET -v $D:/shared:ro,z \
    -e KRB5_CONFIG=/shared/krb5.conf docker.io/library/eclipse-temurin:25-jdk-alpine \
    sh -c 'apk add -q krb5 >/dev/null; sleep infinity' >/dev/null
  sleep 10
  echo "up: KDC, ora.seclume.test with Kerberos, user KALICE as alice@SECLUME.TEST, client"
  ;;
run)
  for j in "$2"/seclume-core.jar "$2"/seclume-oracle.jar "$(dirname "$0")/KerberosProof.java"; do
    podman cp "$j" seclume-ora-krb-client:/tmp/
  done
  J="java --enable-native-access=ALL-UNNAMED -cp /tmp/seclume-core.jar:/tmp/seclume-oracle.jar /tmp/KerberosProof.java ${3:-}"
  podman exec seclume-ora-krb-client sh -c "
    echo '== with a ticket for alice'; kinit -kt /shared/alice.keytab alice@SECLUME.TEST; $J 2>&1 | grep PROOF
    kdestroy; echo '== without a ticket'; $J 2>&1 | grep PROOF"
  ;;
down)
  podman rm -f seclume-ora-krb-client seclume-ora-krb seclume-ora-kdc >/dev/null 2>&1 || true
  podman network rm $NET >/dev/null 2>&1 || true
  find $D -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf $D
  echo "removed"
  ;;
esac
