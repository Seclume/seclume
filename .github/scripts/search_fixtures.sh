#!/usr/bin/env bash
# The search fixtures the Elasticsearch/OpenSearch tests need: Elasticsearch 9
# on 9201 and OpenSearch 3 on 9202, both with TLS from one throwaway CA whose
# server certificate names localhost, 127.0.0.1 and the host's own address.
#
# Writes into the working directory, the files the tests look for:
#   .local-es-ca.pem         the CA (public)
#   .local-es-apikey         an Elasticsearch API key, encoded as ES hands it out
#   .local-os-password       the OpenSearch admin password
# The secrets are made here and copied as files; nothing prints them.
#
#   .github/scripts/search_fixtures.sh <work directory> [host address]
set -euo pipefail
work=$(mkdir -p "${1:?usage: search_fixtures.sh <work directory> [host address]}" && cd "$1" && pwd)
address=${2:-127.0.0.1}
es_image=docker.io/library/elasticsearch:9.5.5
os_image=docker.io/opensearchproject/opensearch:3.9.0

cd "$work"
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=seclume CI search CA" -keyout certs/ca.key -out certs/ca.crt 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=localhost" \
  -keyout certs/server.key -out certs/server.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:%s\nextendedKeyUsage=serverAuth,clientAuth\n' \
  "$address" > certs/ext
openssl x509 -req -in certs/server.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
  -days 2 -extfile certs/ext -out certs/server.crt 2>/dev/null
# OpenSearch wants PKCS#8
openssl pkcs8 -topk8 -nocrypt -in certs/server.key -out certs/server.pk8
rm -f certs/ca.key certs/server.csr certs/ext certs/ca.srl
head -c 24 /dev/urandom | base64 | tr -d '/+=' > es-pw
# OpenSearch's demo setup wants upper, lower, digit and a special character.
echo "Os-$(head -c 18 /dev/urandom | base64 | tr -d '/+=')-9" > os-pw
chmod 644 certs/* && chmod 600 os-pw
# Read by Elasticsearch's user (uid 1000), which insists on 400, 440, 600 or 640.
chmod 400 es-pw && sudo chown 1000:0 es-pw
cd - >/dev/null

docker rm -f seclume-es seclume-os >/dev/null 2>&1 || true
docker run -d --name seclume-es -p 9201:9200 -m 1g \
  -v "$work/certs":/usr/share/elasticsearch/config/slm:ro,z \
  -v "$work/es-pw":/run/es-pw:ro,Z \
  -e discovery.type=single-node -e ES_JAVA_OPTS="-Xms512m -Xmx512m" \
  -e ELASTIC_PASSWORD_FILE=/run/es-pw \
  -e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=true \
  -e xpack.security.http.ssl.key=slm/server.key \
  -e xpack.security.http.ssl.certificate=slm/server.crt \
  -e xpack.security.http.ssl.certificate_authorities=slm/ca.crt \
  -e xpack.security.transport.ssl.enabled=false \
  "$es_image" >/dev/null
docker run -d --name seclume-os -p 9202:9200 -m 1g \
  -v "$work/certs":/usr/share/opensearch/config/slm:ro,z \
  -e discovery.type=single-node -e OPENSEARCH_JAVA_OPTS="-Xms512m -Xmx512m" \
  -e OPENSEARCH_INITIAL_ADMIN_PASSWORD="$(cat "$work/os-pw")" \
  -e plugins.security.ssl.http.pemcert_filepath=slm/server.crt \
  -e plugins.security.ssl.http.pemkey_filepath=slm/server.pk8 \
  -e plugins.security.ssl.http.pemtrustedcas_filepath=slm/ca.crt \
  "$os_image" >/dev/null

up() { # name port password-file user
  for _ in $(seq 1 120); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --cacert "$work/certs/ca.crt" \
      -u "$4:$(sudo cat "$3")" "https://localhost:$2/") || true
    [ "$code" = 200 ] && return 0
    sleep 2
  done
  echo "$1 did not come up"; docker logs "$1" 2>&1 | tail -30; return 1
}
up seclume-es 9201 "$work/es-pw" elastic
up seclume-os 9202 "$work/os-pw" admin

# An API key for the tests, written to a file; its encoded form is what a client sends.
curl -s --cacert "$work/certs/ca.crt" -u "elastic:$(sudo cat "$work/es-pw")" \
  -H 'Content-Type: application/json' -X POST "https://localhost:9201/_security/api_key" \
  -d '{"name":"seclume-test","role_descriptors":{}}' \
  | sed -n 's/.*"encoded":"\([^"]*\)".*/\1/p' > "$work/es-apikey"
test -s "$work/es-apikey"

cp "$work/certs/ca.crt" .local-es-ca.pem
cp "$work/es-apikey" .local-es-apikey
cp "$work/os-pw" .local-os-password
echo "Elasticsearch on 9201, OpenSearch on 9202"
