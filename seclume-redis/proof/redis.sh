#!/bin/bash
# A Redis for LocalRedisTest: the user "orders" with a random password (in an
# ACL file, never on a command line), the default user switched off, a plain
# port and a TLS 1.3 port with a certificate for <address> from a CA of its own.
#   redis.sh up <address clients reach> [plain port] [tls port]    redis.sh down
# Afterwards, copied unread: $DIR/password and $DIR/ca.pem.
set -e
NAME=seclume-redis-test
DIR=/tmp/seclume-redis
IMG=docker.io/library/redis:8
case "$1" in
up)
  ADDRESS=$2; PLAIN=${3:-16379}; TLS=${4:-16380}
  mkdir -p $DIR && chmod 755 $DIR && cd $DIR
  head -c 24 /dev/urandom | base64 | tr -d '/+=' > password; chmod 600 password
  # Only the SHA-256 of the password is in the ACL file, which the server has to read.
  printf 'user default off\nuser orders on #%s ~* &* +@all\n' \
    "$(tr -d '\n' < password | sha256sum | cut -d' ' -f1)" > users.acl
  openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
  openssl req -x509 -new -key ca.key -subj /CN=seclume-redis-test-ca -days 2 -out ca.pem 2>/dev/null
  openssl ecparam -name prime256v1 -genkey -noout -out server.key 2>/dev/null
  openssl req -new -key server.key -subj /CN=redis -out server.csr 2>/dev/null
  printf 'subjectAltName=IP:%s,DNS:localhost\nbasicConstraints=CA:FALSE\n' "$ADDRESS" > ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
    -extfile ext -out server.pem 2>/dev/null
  chmod 644 users.acl server.pem server.key ca.pem   # password stays 600
  podman run -d --name $NAME -p $PLAIN:6379 -p $TLS:6380 -v $DIR:/conf:ro,z $IMG \
    redis-server --aclfile /conf/users.acl --port 6379 --tls-port 6380 \
      --tls-cert-file /conf/server.pem --tls-key-file /conf/server.key \
      --tls-ca-cert-file /conf/ca.pem --tls-auth-clients no --tls-protocols TLSv1.3 >/dev/null
  for i in $(seq 30); do
    podman exec $NAME redis-cli -p 6379 PING 2>/dev/null | grep -q NOAUTH && break
    sleep 1
  done
  echo "redis up on $ADDRESS: plain $PLAIN, TLS 1.3 $TLS, user orders"
  ;;
down)
  podman rm -f $NAME >/dev/null 2>&1 || true
  shred -u $DIR/password $DIR/users.acl $DIR/*.key 2>/dev/null || true
  rm -rf $DIR
  echo "redis removed"
  ;;
esac
