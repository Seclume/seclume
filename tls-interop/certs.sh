#!/usr/bin/env bash
# The certificates for the interop servers: one test CA and the server
# certificates it issues, plus the ones that must be refused - expired, for
# another name, from a CA the client does not trust. Throwaway keys, made
# afresh on every run and never anything but test material.
set -euo pipefail
dir=${1:?usage: certs.sh <directory>}
mkdir -p "$dir"
cd "$dir"

ca() { # name
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
    -subj "/CN=seclume interop $1" -keyout "$1.key" -out "$1.pem" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
}

issue() { # name keyspec ca san days [startdate]
  local name=$1 keyspec=$2 issuer=$3 san=$4 days=$5
  # shellcheck disable=SC2086
  openssl req -new -newkey $keyspec -nodes -subj "/CN=$name" -keyout "$name.key" \
    -out "$name.csr" 2>/dev/null
  printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' \
    "$san" > "$name.ext"
  if [ "$days" = expired ]; then
    # Valid for a day that is over: a CA-signed certificate in the past.
    # Through `openssl ca`, whose -startdate/-enddate every 3.x has; x509's
    # -not_before came only with 3.4.
    mkdir -p ca-db && : > ca-db/index.txt && echo 01 > ca-db/serial
    printf '[ca]\ndefault_ca=d\n[d]\ndir=ca-db\ndatabase=ca-db/index.txt\nserial=ca-db/serial\nnew_certs_dir=ca-db\ndefault_md=sha256\npolicy=p\nunique_subject=no\n[p]\ncommonName=supplied\n' > ca-db/ca.cnf
    openssl ca -batch -config ca-db/ca.cnf -cert "$issuer.pem" -keyfile "$issuer.key" \
      -startdate 20200101000000Z -enddate 20200102000000Z -extfile "$name.ext" \
      -in "$name.csr" -out "$name.pem" -notext 2>/dev/null
  else
    openssl x509 -req -in "$name.csr" -CA "$issuer.pem" -CAkey "$issuer.key" \
      -CAcreateserial -days "$days" -extfile "$name.ext" -out "$name.pem" 2>/dev/null
  fi
  cat "$name.pem" "$issuer.pem" > "$name.chain.pem"
  # PKCS#8, which every server here reads.
  openssl pkcs8 -topk8 -nocrypt -in "$name.key" -out "$name.p8.key"
}

ca ca
ca stranger
issue ecdsa256 "ec -pkeyopt ec_paramgen_curve:P-256" ca DNS:localhost 2
issue ecdsa384 "ec -pkeyopt ec_paramgen_curve:P-384" ca DNS:localhost 2
issue rsa2048 "rsa:2048" ca DNS:localhost 2
issue expired "ec -pkeyopt ec_paramgen_curve:P-256" ca DNS:localhost expired
issue othername "ec -pkeyopt ec_paramgen_curve:P-256" ca DNS:not-localhost.example 2
issue strangers "ec -pkeyopt ec_paramgen_curve:P-256" stranger DNS:localhost 2
# The JDK's server reads PKCS#12.
openssl pkcs12 -export -in ecdsa256.chain.pem -inkey ecdsa256.key -out ecdsa256.p12 \
  -passout pass:interop -name server
openssl pkcs12 -export -in rsa2048.chain.pem -inkey rsa2048.key -out rsa2048.p12 \
  -passout pass:interop -name server
echo "certificates in $dir"
