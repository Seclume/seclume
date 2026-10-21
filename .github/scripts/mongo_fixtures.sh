#!/usr/bin/env bash
# The MongoDB fixtures the MongoDB tests need, as on the developer's server:
# a standalone on 27017 and a replica set slm-rs on 27021-27023, MongoDB 8,
# TLS required, user seclume_test with SCRAM-SHA-1 and SCRAM-SHA-256 (so a
# test can show SHA-1 is never taken), fail points allowed on the set.
#
# Writes .local-mongo-password, .local-mongo-ca.pem and .local-mongo-rs-ca.pem
# into the working directory - the files the tests look for.
#
#   .github/scripts/mongo_fixtures.sh <work directory>
set -euo pipefail
work=$(mkdir -p "${1:?usage: mongo_fixtures.sh <work directory>}" && cd "$1" && pwd)
image=docker.io/library/mongo:8.0
# The image hands rseq to tcmalloc (glibc.pthread.rseq=0). On kernels 6.19 to
# 7.0.13 that crashes, so mongod refuses to start there (SERVER-121912); with
# glibc keeping rseq, tcmalloc does without it and mongod starts.
rseq=(-e GLIBC_TUNABLES=glibc.pthread.rseq=1)

# One throwaway CA; the server certificate also authenticates the members to
# each other, so it needs clientAuth as well as serverAuth.
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=seclume CI mongo CA" -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
  -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile ext -out server.crt 2>/dev/null
cat server.crt server.key > server.pem
rm -f ca.key server.key server.csr ext ca.srl
# MONGODB-X509: a client CA the servers trust besides their own, certuser from
# it, and two that must be refused - another CA's and a self-signed one with the
# same name. Their keys stay the runner's; only the CA goes into ca.pem.
mkdir -p certauth
client() { # name subject issuer-key issuer-cert
  openssl ecparam -name prime256v1 -genkey -noout -out certauth/$1.key
  openssl req -new -key certauth/$1.key -subj "/CN=$2" -out certauth/$1.csr 2>/dev/null
  echo 'extendedKeyUsage=clientAuth' > certauth/ext
  openssl x509 -req -in certauth/$1.csr -CA $4 -CAkey $3 -CAcreateserial -days 2     -extfile certauth/ext -out certauth/$1.crt 2>/dev/null
}
openssl ecparam -name prime256v1 -genkey -noout -out certauth/ca.key
openssl req -x509 -new -key certauth/ca.key -days 2 -subj "/CN=seclume CI client CA"   -out certauth/ca.crt 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out certauth/other-ca.key
openssl req -x509 -new -key certauth/other-ca.key -days 2 -subj "/CN=a stranger's CA"   -out certauth/other-ca.crt 2>/dev/null
client certuser certuser certauth/ca.key certauth/ca.crt
client stranger certuser certauth/other-ca.key certauth/other-ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out certauth/forged.key
openssl req -x509 -new -key certauth/forged.key -days 2 -subj "/CN=certuser"   -addext "extendedKeyUsage=clientAuth" -out certauth/forged.crt 2>/dev/null
rm -f certauth/*.csr certauth/ext certauth/*.srl certauth/ca.key certauth/other-ca.key
cat certauth/ca.crt >> ca.pem
head -c 24 /dev/urandom | base64 | tr -d '/+=' > pw
openssl rand -base64 756 > keyfile
chmod 400 keyfile server.pem pw
sudo chown 999:999 keyfile server.pem pw ca.pem
cd - >/dev/null

tls=(--tlsMode requireTLS --tlsCertificateKeyFile /certs/server.pem --tlsCAFile /certs/ca.pem
     --tlsAllowConnectionsWithoutCertificates --wiredTigerCacheSizeGB 0.25)

docker run -d --name mongo --network host -v "$work":/certs:ro "${rseq[@]}" \
  -e MONGO_INITDB_ROOT_USERNAME=seclume_test -e MONGO_INITDB_ROOT_PASSWORD_FILE=/certs/pw \
  "$image" mongod --port 27017 "${tls[@]}" >/dev/null

for i in 1 2 3; do
  docker run -d --name mongo-rs$i --network host -v "$work":/certs:ro "${rseq[@]}" "$image" \
    mongod --replSet slm-rs --port $((27020 + i)) --bind_ip_all --keyFile /certs/keyfile \
      "${tls[@]}" --setParameter enableTestCommands=1 >/dev/null
done

ready() { # port
  for _ in $(seq 1 60); do
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
    sleep 1
  done
  echo "nothing listens on $1"; docker logs mongo 2>&1 | tail -20; return 1
}
for port in 27021 27022 27023; do ready $port; done

# The set and its user, through the localhost exception; the password is read
# by mongosh from the file, never on a command line.
cat > "$work/init.js" <<'JS'
rs.initiate({_id: 'slm-rs', members: [
  {_id: 0, host: '127.0.0.1:27021', priority: 2},
  {_id: 1, host: '127.0.0.1:27022'},
  {_id: 2, host: '127.0.0.1:27023'}]});
for (let i = 0; i < 120 && !db.hello().isWritablePrimary; i++) { sleep(500); }
if (!db.hello().isWritablePrimary) { throw new Error('no primary'); }
const pwd = require('fs').readFileSync('/certs/pw', 'utf8').trim();
db.getSiblingDB('admin').createUser({user: 'seclume_test', pwd: pwd, roles: ['root'],
    mechanisms: ['SCRAM-SHA-1', 'SCRAM-SHA-256']});
db.getSiblingDB('admin').auth('seclume_test', pwd);
db.getSiblingDB('$external').createUser({user: 'CN=certuser',
    roles: [{role: 'readWrite', db: 'seclume_test'}]});
JS
sudo chown 999:999 "$work/init.js"
docker exec mongo-rs1 mongosh --quiet --tls --tlsCAFile /certs/ca.pem --host localhost \
  --port 27021 /certs/init.js

# The standalone's entrypoint creates its user and restarts: ready when it
# answers on 27017 after that.
# Its first mongod is a temporary one for that; the log says when it is done.
for _ in $(seq 1 90); do
  docker logs mongo 2>&1 | grep -q 'MongoDB init process complete' && break
  sleep 1
done
sleep 3
ready 27017

sudo cat "$work/pw" > .local-mongo-password
cp "$work/ca.pem" .local-mongo-ca.pem
cp "$work/ca.pem" .local-mongo-rs-ca.pem
rm -rf .local-certauth && cp -r "$work/certauth" .local-certauth
echo "MongoDB standalone on 27017, replica set slm-rs on 27021-27023"
