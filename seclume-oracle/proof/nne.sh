#!/bin/sh
# An Oracle Free that requires Native Network Encryption and data integrity, for
# LocalOracleNneTest:
#
#   nne.sh up [port]   Oracle Free 23 on <port> (default 1525), sqlnet.ora with
#                      SQLNET.ENCRYPTION_SERVER and SQLNET.CRYPTO_CHECKSUM_SERVER
#                      REQUIRED (AES256, SHA256); the app user's password written
#                      to $D/password, to be copied unread
#   nne.sh down        all of it removed
set -eu
D=/tmp/seclume-ora-nne
NAME=seclume-ora-nne
case "$1" in
up)
  PORT=${2:-1525}
  mkdir -p $D && chmod 700 $D
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/password
  head -c 18 /dev/urandom | base64 | tr -d '/+=' > $D/admin
  chmod 600 $D/password $D/admin
  printf 'ORACLE_PASSWORD=%s\nAPP_USER=seclume_test\nAPP_USER_PASSWORD=%s\n' \
    "$(cat $D/admin)" "$(cat $D/password)" > $D/env
  chmod 600 $D/env
  podman run -d --name $NAME -p $PORT:1521 --env-file $D/env \
    docker.io/gvenzl/oracle-free:23-slim >/dev/null
  shred -u $D/env
  for i in $(seq 1 120); do
    podman logs $NAME 2>&1 | grep -q "DATABASE IS READY TO USE" && break
    sleep 5
  done
  podman exec $NAME sh -c 'cat >> "$ORACLE_HOME/network/admin/sqlnet.ora" <<EOF
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA256)
EOF'
  echo "up: Oracle Free on $PORT, NNE and checksums required (AES256, SHA256)"
  ;;
down)
  podman rm -f $NAME >/dev/null 2>&1 || true
  find $D -type f -exec shred -u {} \; 2>/dev/null || true
  rm -rf $D
  echo "removed"
  ;;
esac
