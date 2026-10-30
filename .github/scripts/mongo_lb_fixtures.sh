#!/usr/bin/env bash
# A sharded MongoDB cluster behind a load balancer, for loadBalanced=true:
# one config server, one shard, two mongos with a load balancer port, and
# HAProxy in front of them on 27050, round robin with the PROXY protocol - so
# that consecutive connections reach different routers, and a cursor or a
# transaction that does not keep its connection fails.
#
# TLS required, user seclume_test with SCRAM-SHA-256. Writes
# .local-mongo-lb-password and .local-mongo-lb-ca.pem into the working
# directory - the files the tests look for.
#
#   .github/scripts/mongo_lb_fixtures.sh <work directory> [address the tests use]
set -euo pipefail
work=$(mkdir -p "${1:?usage: mongo_lb_fixtures.sh <work directory> [address]}" && cd "$1" && pwd)
address=${2:-127.0.0.1}
image=${MONGO_IMAGE:-docker.io/library/mongo:8.0}
balancer=docker.io/library/haproxy:3.4
# The image hands rseq to tcmalloc (glibc.pthread.rseq=0). On kernels 6.19 to
# 7.0.13 that crashes, so mongod refuses to start there (SERVER-121912); with
# glibc keeping rseq, tcmalloc does without it and mongod starts.
rseq=(-e GLIBC_TUNABLES=glibc.pthread.rseq=1)
net=slm-lb

# One throwaway CA. The members reach each other by container name, and check
# the names: they are all in the certificate, with the address the tests use.
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=seclume CI mongo lb CA" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
  -keyout server.key -out server.csr 2>/dev/null
san="DNS:localhost,IP:127.0.0.1,DNS:slm-cfg,DNS:slm-shard,DNS:slm-mongos1,DNS:slm-mongos2"
case "$address" in
  *[!0-9.]*) san="$san,DNS:$address" ;;
  127.0.0.1) ;;
  *) san="$san,IP:$address" ;;
esac
printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$san" > ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile ext -out server.crt 2>/dev/null
cat server.crt server.key > server.pem
rm -f ca.key server.key server.csr ext ca.srl server.crt
head -c 24 /dev/urandom | base64 | tr -d '/+=' > pw
openssl rand -base64 756 > keyfile
cat > haproxy.cfg <<'CFG'
defaults
  mode tcp
  timeout connect 5s
  timeout client 1h
  timeout server 1h
frontend mongodb
  bind :27050
  default_backend routers
backend routers
  balance roundrobin
  server mongos1 slm-mongos1:27050 send-proxy-v2
  server mongos2 slm-mongos2:27050 send-proxy-v2
CFG
chmod 400 keyfile server.pem pw
chmod 444 haproxy.cfg ca.pem
sudo chown 999:999 keyfile server.pem pw ca.pem
cd - >/dev/null

docker network create "$net" >/dev/null 2>&1 || true
tls=(--bind_ip_all --keyFile /certs/keyfile --tlsMode requireTLS
     --tlsCertificateKeyFile /certs/server.pem --tlsCAFile /certs/ca.pem
     --tlsAllowConnectionsWithoutCertificates)
run() { # name, then the command
  local name=$1; shift
  docker run -d --name "$name" --hostname "$name" --network "$net" \
    -v "$work":/certs:ro,z "${rseq[@]}" "$image" "$@" >/dev/null
}
mongosh() { # container port, then mongosh arguments
  local name=$1 port=$2; shift 2
  docker exec "$name" mongosh --quiet --tls --tlsCAFile /certs/ca.pem --host localhost \
    --port "$port" "$@"
}
ready() { # container port
  for _ in $(seq 1 90); do
    mongosh "$1" "$2" --eval 'db.runCommand({ping: 1}).ok' >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "$1 does not answer on $2"; docker logs "$1" 2>&1 | tail -20; return 1
}

run slm-cfg mongod --configsvr --replSet slm-cfg --port 27019 "${tls[@]}" \
  --wiredTigerCacheSizeGB 0.25
run slm-shard mongod --shardsvr --replSet slm-shard --port 27018 "${tls[@]}" \
  --wiredTigerCacheSizeGB 0.25
ready slm-cfg 27019
ready slm-shard 27018
mongosh slm-cfg 27019 --eval "rs.initiate({_id: 'slm-cfg', configsvr: true,
  members: [{_id: 0, host: 'slm-cfg:27019'}]})" >/dev/null
mongosh slm-shard 27018 --eval "rs.initiate({_id: 'slm-shard',
  members: [{_id: 0, host: 'slm-shard:27018'}]})" >/dev/null

for i in 1 2; do
  run slm-mongos$i mongos --configdb slm-cfg/slm-cfg:27019 --port 27017 "${tls[@]}" \
    --setParameter loadBalancerPort=27050
done
ready slm-mongos1 27017
ready slm-mongos2 27017

# The user through the first router's localhost exception, then the shard;
# the password is read by mongosh from the file, never on a command line.
cat > "$work/init.js" <<'JS'
const pwd = require('fs').readFileSync('/certs/pw', 'utf8').trim();
db.getSiblingDB('admin').createUser({user: 'seclume_test', pwd: pwd, roles: ['root'],
    mechanisms: ['SCRAM-SHA-256']});
db.getSiblingDB('admin').auth('seclume_test', pwd);
for (let i = 0; i < 60; i++) {
  try { sh.addShard('slm-shard/slm-shard:27018'); break; } catch (e) { sleep(1000); }
}
if (db.getSiblingDB('config').shards.countDocuments() !== 1) { throw new Error('no shard'); }
JS
sudo chown 999:999 "$work/init.js"
mongosh slm-mongos1 27017 /certs/init.js

docker run -d --name slm-haproxy --network "$net" -p 27050:27050 \
  -v "$work/haproxy.cfg":/usr/local/etc/haproxy/haproxy.cfg:ro,z "$balancer" >/dev/null
for _ in $(seq 1 30); do
  (exec 3<>/dev/tcp/127.0.0.1/27050) 2>/dev/null && break
  sleep 1
done

sudo cat "$work/pw" > .local-mongo-lb-password
cp "$work/ca.pem" .local-mongo-lb-ca.pem
echo "MongoDB behind a load balancer on 27050: two mongos, one shard"
