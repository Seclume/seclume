#!/usr/bin/env bash
# The fixtures of mongo_fixtures.sh without containers, for the runners that
# have none (Windows, macOS): the same standalone on 27017 and replica set
# slm-rs on 27021-27023 of mongod processes, TLS required, user seclume_test
# with SCRAM-SHA-1 and SCRAM-SHA-256, CN=certuser for MONGODB-X509, fail
# points allowed on the set. Not the load-balanced cluster, which needs
# HAProxy and a sharded cluster.
#
# Writes .local-mongo-password, .local-mongo-ca.pem, .local-mongo-rs-ca.pem
# and .local-certauth/ into the working directory - the files the tests look for.
#
#   .github/scripts/mongo_native_fixtures.sh <work directory> <mongod's bin directory>
#
# OPENSSL may name the openssl to use (macOS's own is LibreSSL).
set -euo pipefail
work=$(mkdir -p "${1:?usage: mongo_native_fixtures.sh <work> <bin>}" && cd "$1" && pwd)
bin=${2:?usage: mongo_native_fixtures.sh <work> <bin>}
openssl=${OPENSSL:-openssl}
mongosh=${MONGOSH:-mongosh}

# On Windows, Git's bash would rewrite "/CN=..." into a path; the tools here
# get their paths in the mixed form C:/... instead, which every one of them reads.
if [[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]]; then
  export MSYS2_ARG_CONV_EXCL='*'
  path() { cygpath -m "$1"; }
else
  path() { printf '%s' "$1"; }
fi
w=$(path "$work")

cd "$work"
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=seclume CI mongo CA" -keyout ca.key -out ca.pem 2>/dev/null
"$openssl" req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
  -keyout server.key -out server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n' > ext
"$openssl" x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 \
  -extfile ext -out server.crt 2>/dev/null
cat server.crt server.key > server.pem
rm -f ca.key server.key server.csr ext ca.srl
mkdir -p certauth
client() { # name subject issuer-key issuer-cert
  "$openssl" ecparam -name prime256v1 -genkey -noout -out certauth/$1.key
  "$openssl" req -new -key certauth/$1.key -subj "/CN=$2" -out certauth/$1.csr 2>/dev/null
  echo 'extendedKeyUsage=clientAuth' > certauth/ext
  "$openssl" x509 -req -in certauth/$1.csr -CA $4 -CAkey $3 -CAcreateserial -days 2 \
    -extfile certauth/ext -out certauth/$1.crt 2>/dev/null
}
"$openssl" ecparam -name prime256v1 -genkey -noout -out certauth/ca.key
"$openssl" req -x509 -new -key certauth/ca.key -days 2 -subj "/CN=seclume CI client CA" \
  -out certauth/ca.crt 2>/dev/null
"$openssl" ecparam -name prime256v1 -genkey -noout -out certauth/other-ca.key
"$openssl" req -x509 -new -key certauth/other-ca.key -days 2 -subj "/CN=a stranger's CA" \
  -out certauth/other-ca.crt 2>/dev/null
client certuser certuser certauth/ca.key certauth/ca.crt
client stranger certuser certauth/other-ca.key certauth/other-ca.crt
"$openssl" ecparam -name prime256v1 -genkey -noout -out certauth/forged.key
"$openssl" req -x509 -new -key certauth/forged.key -days 2 -subj "/CN=certuser" \
  -addext "extendedKeyUsage=clientAuth" -out certauth/forged.crt 2>/dev/null
rm -f certauth/*.csr certauth/ext certauth/*.srl certauth/ca.key certauth/other-ca.key
cat certauth/ca.crt >> ca.pem
"$openssl" rand -base64 18 | tr -d '/+=\n' > pw
"$openssl" rand -base64 756 > keyfile
chmod 600 keyfile server.pem pw
cd - >/dev/null

tls=(--tlsMode requireTLS --tlsCertificateKeyFile "$w/server.pem" --tlsCAFile "$w/ca.pem"
     --tlsAllowConnectionsWithoutCertificates --wiredTigerCacheSizeGB 0.25 --bind_ip 127.0.0.1)

start() { # name port extra...
  local name=$1 port=$2
  shift 2
  mkdir -p "$work/$name"
  "$bin/mongod" --port "$port" --dbpath "$w/$name" --logpath "$w/$name.log" "${tls[@]}" "$@" \
    > /dev/null 2>&1 &
}
start standalone 27017 --auth
for i in 1 2 3; do
  start rs$i $((27020 + i)) --replSet slm-rs --keyFile "$w/keyfile" \
    --setParameter enableTestCommands=1
done

ready() { # port name
  for _ in $(seq 1 90); do
    (exec 3<>/dev/tcp/127.0.0.1/"$1") 2>/dev/null && return 0
    sleep 1
  done
  echo "nothing listens on $1"; tail -30 "$work/$2.log" || true; return 1
}
ready 27017 standalone
for i in 1 2 3; do ready $((27020 + i)) rs$i; done

# Users through the localhost exception; the password is read by mongosh from
# the file, never from a command line.
cat > "$work/init-rs.js" <<JS
rs.initiate({_id: 'slm-rs', members: [
  {_id: 0, host: '127.0.0.1:27021', priority: 2},
  {_id: 1, host: '127.0.0.1:27022'},
  {_id: 2, host: '127.0.0.1:27023'}]});
for (let i = 0; i < 120 && !db.hello().isWritablePrimary; i++) { sleep(500); }
if (!db.hello().isWritablePrimary) { throw new Error('no primary'); }
const pwd = require('fs').readFileSync('$w/pw', 'utf8').trim();
db.getSiblingDB('admin').createUser({user: 'seclume_test', pwd: pwd, roles: ['root'],
    mechanisms: ['SCRAM-SHA-1', 'SCRAM-SHA-256']});
db.getSiblingDB('admin').auth('seclume_test', pwd);
db.getSiblingDB('\$external').createUser({user: 'CN=certuser',
    roles: [{role: 'readWrite', db: 'seclume_test'}]});
JS
cat > "$work/init-standalone.js" <<JS
const pwd = require('fs').readFileSync('$w/pw', 'utf8').trim();
db.getSiblingDB('admin').createUser({user: 'seclume_test', pwd: pwd, roles: ['root'],
    mechanisms: ['SCRAM-SHA-1', 'SCRAM-SHA-256']});
JS
"$mongosh" --quiet --tls --tlsCAFile "$w/ca.pem" --host localhost --port 27021 "$w/init-rs.js"
"$mongosh" --quiet --tls --tlsCAFile "$w/ca.pem" --host localhost --port 27017 \
  "$w/init-standalone.js"

cp "$work/pw" .local-mongo-password
cp "$work/ca.pem" .local-mongo-ca.pem
cp "$work/ca.pem" .local-mongo-rs-ca.pem
rm -rf .local-certauth && cp -r "$work/certauth" .local-certauth
echo "MongoDB standalone on 27017, replica set slm-rs on 27021-27023 ($("$bin/mongod" --version | head -1))"
